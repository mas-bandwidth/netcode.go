/*
    C reference oracle for the differential test in c_differential_test.go.

    For each fixed input fed by the Go test this program runs the C packet
    reader and prints exactly one line, in the same form the port side prints:

        <n> <packet type or refused> <sequence> <length>

    where <packet type or refused> is the numeric packet type 0..6 for a packet
    that was read, or the literal "refused"; <sequence> is the sequence number
    the reader saw (0 when none was read); and <length> is the input byte
    length. No sockets and no wall clock: keys, protocol id and the current
    timestamp are fixed constants, and the inputs arrive as a framed binary
    file.

    Build (see c_differential_test.go):

        cc -O2 -ffp-contract=off -I$NETCODE_C_DIR -I$NETCODE_C_DIR/sodium \
            -o oracle testdata/c/oracle.c $NETCODE_C_DIR/sodium/sodium.c -lm

    Run:

        ./oracle inputs.bin

    inputs.bin is written by the Go test as (all integers little endian):

        uint32 count
        then, count times:
            uint32 length
            uint8  data[length]
            uint32 replay_group   // 0 = fresh replay protection;
                                  // the same non-zero value shares one

    The read path reaches the file-local netcode_read_packet via
    #include "netcode.c". Its exact signature and the replay setup below
    must match the C checkout named by NETCODE_C_DIR; the single call is
    confined to oracle_read_packet so a mismatch is a one-place fix.
*/

#include <time.h>

// The included reference reads time(NULL) during server start and packet
// processing. Give every step the same explicit timestamp as the Go script.
static time_t oracle_fixed_time( time_t * result )
{
    const time_t fixed = (time_t) 1700000000;
    if ( result ) *result = fixed;
    return fixed;
}

#define time(arg) oracle_fixed_time(arg)
#define NETCODE_ENABLE_TESTS 1
#include "netcode.c"
#undef time

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ORACLE_PROTOCOL_ID       0x1122334455667788ULL
#define ORACLE_CURRENT_TIMESTAMP 0ULL
#define ORACLE_MAX_INPUT_BYTES   4096
#define ORACLE_MAX_GROUPS        64

static void oracle_pattern( uint8_t * data, int bytes, int multiplier, int offset )
{
    int i;
    for ( i = 0; i < bytes; i++ )
    {
        data[i] = (uint8_t) ( i * multiplier + offset );
    }
}

static void oracle_packet_key( uint8_t * key )  { oracle_pattern( key, NETCODE_KEY_BYTES, 7, 1 ); }
static void oracle_private_key( uint8_t * key ) { oracle_pattern( key, NETCODE_KEY_BYTES, 11, 3 ); }

static uint32_t read_u32( FILE * f )
{
    uint8_t b[4];
    if ( fread( b, 1, 4, f ) != 4 )
    {
        fprintf( stderr, "oracle: short read\n" );
        exit( 1 );
    }
    return (uint32_t) b[0] | ( (uint32_t) b[1] << 8 ) | ( (uint32_t) b[2] << 16 ) | ( (uint32_t) b[3] << 24 );
}

#ifndef NETCODE_CONNECTION_NUM_PACKETS
#define NETCODE_CONNECTION_NUM_PACKETS 7
#endif

/*
    Reads one input packet through the C packet reader and prints the result
    line. replay_protection must be reset before the first call for its group
    and kept across calls that share the group. Returns 1 when the packet was
    read, 0 when it was refused.
*/
static int oracle_read_packet( uint8_t * buffer, int buffer_length,
                               struct netcode_replay_protection_t * replay_protection,
                               uint64_t * out_sequence,
                               uint8_t * out_type )
{
    uint8_t packet_key[NETCODE_KEY_BYTES];
    uint8_t private_key[NETCODE_KEY_BYTES];
    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    uint64_t sequence = 0;
    void * packet;

    oracle_packet_key( packet_key );
    oracle_private_key( private_key );
    memset( allowed_packets, 1, sizeof( allowed_packets ) );

    packet = netcode_read_packet( buffer,
                                  buffer_length,
                                  &sequence,
                                  packet_key,
                                  ORACLE_PROTOCOL_ID,
                                  ORACLE_CURRENT_TIMESTAMP,
                                  0ULL,
                                  UINT64_MAX,
                                  private_key,
                                  allowed_packets,
                                  replay_protection,
                                  NULL,
                                  NULL );

    *out_sequence = sequence;

    if ( packet == NULL )
    {
        return 0;
    }

    *out_type = (uint8_t) ( *( (int*) packet ) );
    free( packet );
    return 1;
}

static void oracle_setup( void )
{
}

/*
    Receive drain mode.

    Drives the C server or client receive loop with a scripted override that
    plays the same queues the Go port test plays, and prints one line per case
    in the form:

        <queue> <server|client> consumed <n> processed <m>

    consumed counts every datagram the override handed out, including the
    skipped zero-length datagrams; processed counts the datagrams that reached
    the packet processor. The override is the only observer, so the two sides
    are compared on the port's pull behaviour, not on internal counters.

    Input file (all integers little endian):

        uint32 case_count
        then, per case:
            uint32 name_length
            uint8  name[name_length]
            uint32 side            // 0 = server, 1 = client
            uint32 item_count
            int32  item[item_count] // >0 junk length, -1 skip, -2 would-block

    The server and client create/start/update/destroy calls must match the C
    checkout named by NETCODE_C_DIR; this leg is unverified without one.
*/

#define ORACLE_RECEIVE_MAX_ITEMS ( 64 * NETCODE_MAX_CLIENTS + 11 )
#define ORACLE_RECEIVE_MAX_NAME  128

static int oracle_receive_items[ORACLE_RECEIVE_MAX_ITEMS];
static int oracle_receive_count;
static int oracle_receive_index;
static int oracle_receive_consumed;
static int oracle_receive_processed;

/*
    The C reference refuses to create a server or client with
    override_send_and_receive set unless both the send and receive callbacks
    are non-NULL (netcode.c returns the missing-override-callback create
    error otherwise). This leg only observes the receive loop, so the send
    callback is a no-op that drops every packet. Its signature mirrors
    netcode.h: void (*)(void*, struct netcode_address_t*, NETCODE_CONST
    uint8_t*, int).
*/
static void oracle_send_override( void * context, struct netcode_address_t * to,
                                  NETCODE_CONST uint8_t * packet_data, int packet_bytes )
{
    (void) context;
    (void) to;
    (void) packet_data;
    (void) packet_bytes;
}

static int oracle_receive_override( void * context, struct netcode_address_t * from,
                                    uint8_t * packet_data, int max_packet_size )
{
    int item;

    (void) context;
    (void) from;

    if ( oracle_receive_index >= oracle_receive_count )
        return 0;

    item = oracle_receive_items[oracle_receive_index++];

    if ( item == -2 )
        return 0;

    if ( item < 0 )
    {
        oracle_receive_consumed++;
        return -1;
    }

    if ( item > max_packet_size )
        item = max_packet_size;

    oracle_receive_consumed++;
    oracle_receive_processed++;

    memset( packet_data, 0x11, item );
    return item;
}

static void oracle_receive_server( void )
{
    struct netcode_server_config_t config;
    struct netcode_server_t * server;
    uint8_t private_key[NETCODE_KEY_BYTES];

    memset( &config, 0, sizeof( config ) );
    oracle_private_key( private_key );
    config.protocol_id = ORACLE_PROTOCOL_ID;
    memcpy( config.private_key, private_key, NETCODE_KEY_BYTES );
    config.override_send_and_receive = 1;
    config.send_packet_override = oracle_send_override;
    config.receive_packet_override = oracle_receive_override;

    server = netcode_server_create( "127.0.0.1:40000", &config, 0.0 );
    if ( server == NULL )
        return;

    netcode_server_start( server, 1 );
    netcode_server_update( server, 1.0 );
    netcode_server_destroy( server );
}

static void oracle_receive_client( void )
{
    struct netcode_client_config_t config;
    struct netcode_client_t * client;

    memset( &config, 0, sizeof( config ) );
    config.override_send_and_receive = 1;
    config.send_packet_override = oracle_send_override;
    config.receive_packet_override = oracle_receive_override;

    client = netcode_client_create( "127.0.0.1:41000", &config, 0.0 );
    if ( client == NULL )
        return;

    netcode_client_update( client, 1.0 );
    netcode_client_destroy( client );
}

static int oracle_receive_main( const char * path )
{
    FILE * f;
    uint32_t case_count, c;

    f = fopen( path, "rb" );
    if ( !f )
    {
        fprintf( stderr, "oracle: could not open %s\n", path );
        return 1;
    }

    if ( netcode_init() != NETCODE_OK )
    {
        fprintf( stderr, "oracle: netcode_init failed\n" );
        return 1;
    }

    case_count = read_u32( f );

    for ( c = 0; c < case_count; c++ )
    {
        char name[ORACLE_RECEIVE_MAX_NAME + 1];
        uint32_t name_length = read_u32( f );
        uint32_t side, item_count, i;

        if ( name_length > ORACLE_RECEIVE_MAX_NAME )
        {
            fprintf( stderr, "oracle: name too long\n" );
            return 1;
        }
        if ( fread( name, 1, name_length, f ) != name_length )
        {
            fprintf( stderr, "oracle: short name\n" );
            return 1;
        }
        name[name_length] = '\0';

        side = read_u32( f );
        item_count = read_u32( f );
        if ( item_count > ORACLE_RECEIVE_MAX_ITEMS )
        {
            fprintf( stderr, "oracle: too many items\n" );
            return 1;
        }

        for ( i = 0; i < item_count; i++ )
            oracle_receive_items[i] = (int) read_u32( f );

        oracle_receive_count = (int) item_count;
        oracle_receive_index = 0;
        oracle_receive_consumed = 0;
        oracle_receive_processed = 0;

        if ( side == 1 )
            oracle_receive_client();
        else
            oracle_receive_server();

        printf( "%s %s consumed %d processed %d\n", name,
                side == 1 ? "client" : "server",
                oracle_receive_consumed, oracle_receive_processed );
    }

    fclose( f );
    netcode_term();

    return 0;
}

static int oracle_challenge_read( struct netcode_address_t * to, uint8_t * key,
                                  struct netcode_connection_challenge_packet_t * challenge )
{
    uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS] = { 0 };
    allowed[NETCODE_CONNECTION_CHALLENGE_PACKET] = 1;
    int found = 0;
    for ( int i = 0; i < test_script.num_sent; i++ )
    {
        if ( !netcode_address_equal( &test_script.sent_to[i], to ) )
            continue;
        uint8_t data[NETCODE_MAX_PACKET_BYTES];
        memcpy( data, test_script.sent_data[i], test_script.sent_bytes[i] );
        uint64_t sequence = 0;
        struct netcode_connection_challenge_packet_t * packet =
            (struct netcode_connection_challenge_packet_t*) netcode_read_packet(
                data, test_script.sent_bytes[i], &sequence, key, TEST_PROTOCOL_ID,
                0, 0, UINT64_MAX, NULL, allowed, NULL, NULL, NULL );
        if ( packet )
        {
            *challenge = *packet;
            found = 1;
            free( packet );
        }
    }
    return found;
}

static void oracle_challenge_step( const char * name, struct netcode_server_t * server )
{
    const uint64_t ids[] = { 0x1111, 0x2222, 0x3333 };
    printf( "%s connected", name );
    for ( int i = 0; i < 3; i++ )
        if ( test_script_find_client_by_id( server, ids[i] ) >= 0 )
            printf( " %04llx", (unsigned long long) ids[i] );
    printf( " userdata" );
    for ( int i = 0; i < 3; i++ )
    {
        int slot = test_script_find_client_by_id( server, ids[i] );
        if ( slot >= 0 )
            printf( " %02x", (unsigned) ((uint8_t*) netcode_server_client_user_data( server, slot ))[0] );
    }
    printf( "\n" );
}

// The input is the three exact 2048-byte connect tokens also presented to Go.
static int oracle_challenge_main( const char * path, const char * trace_path )
{
    FILE * f = fopen( path, "rb" );
    if ( !f )
        return 1;
    uint8_t token_data[3][NETCODE_CONNECT_TOKEN_BYTES];
    struct netcode_connect_token_t tokens[3];
    for ( int i = 0; i < 3; i++ )
    {
        if ( fread( token_data[i], 1, NETCODE_CONNECT_TOKEN_BYTES, f ) != NETCODE_CONNECT_TOKEN_BYTES ||
             netcode_read_connect_token( token_data[i], NETCODE_CONNECT_TOKEN_BYTES, &tokens[i] ) != NETCODE_OK )
        {
            fclose( f );
            return 1;
        }
    }
    fclose( f );
    if ( netcode_init() != NETCODE_OK )
        return 1;
    memset( &test_script, 0, sizeof( test_script ) );
    struct netcode_server_config_t config;
    netcode_default_server_config( &config );
    config.protocol_id = TEST_PROTOCOL_ID;
    config.override_send_and_receive = 1;
    config.send_packet_override = test_script_send_packet;
    config.receive_packet_override = test_script_receive_packet;
    memcpy( config.private_key, private_key, NETCODE_KEY_BYTES );
    struct netcode_server_t * server = netcode_server_create( "[::1]:40000", &config, 0.0 );
    if ( !server )
        return 1;
    netcode_server_start( server, 4 );
    for ( int i = 0; i < NETCODE_KEY_BYTES; i++ )
        server->challenge_key[i] = (uint8_t) ( 0xa0 + i );
    server->config.max_connect_token_lifetime = 600;
    server->min_connect_token_expire_timestamp = 1700000000ULL + 599;
    struct netcode_address_t x, y;
    if ( netcode_parse_address( "[::1]:50000", &x ) != NETCODE_OK ||
         netcode_parse_address( "[::1]:50001", &y ) != NETCODE_OK )
        return 1;
    struct netcode_connection_challenge_packet_t a, b, c_first, c_second;
    double current_time = 0.0;
    test_script_add_connection_request( &x, &tokens[0] );
    netcode_server_update( server, current_time );
    if ( !oracle_challenge_read( &x, tokens[0].server_to_client_key, &a ) ) return 1;
    oracle_challenge_step( "request-a", server );
    current_time += 0.1;
    test_script_add_connection_request( &y, &tokens[1] );
    netcode_server_update( server, current_time );
    if ( !oracle_challenge_read( &y, tokens[1].server_to_client_key, &b ) ) return 1;
    oracle_challenge_step( "request-b", server );
    current_time += 0.1;
    test_script_add_connection_response( &y, 1, tokens[1].client_to_server_key, &a );
    netcode_server_update( server, current_time );
    oracle_challenge_step( "response-b-with-a", server );
    current_time += 0.1;
    test_script_add_connection_response( &y, 2, tokens[1].client_to_server_key, &b );
    netcode_server_update( server, current_time );
    oracle_challenge_step( "response-b-with-b", server );
    current_time += 0.1;
    test_script_add_connection_request( &x, &tokens[2] );
    netcode_server_update( server, current_time );
    if ( !oracle_challenge_read( &x, tokens[2].server_to_client_key, &c_first ) ) return 1;
    oracle_challenge_step( "request-c-first", server );
    current_time += 0.1;
    test_script_add_connection_request( &x, &tokens[2] );
    netcode_server_update( server, current_time );
    if ( !oracle_challenge_read( &x, tokens[2].server_to_client_key, &c_second ) ) return 1;
    oracle_challenge_step( "request-c-second", server );
    current_time += 0.1;
    test_script_add_connection_response( &x, 1, tokens[2].client_to_server_key, &a );
    netcode_server_update( server, current_time );
    oracle_challenge_step( "response-c-with-a", server );
    current_time += 0.1;
    test_script_add_connection_response( &x, 2, tokens[2].client_to_server_key, &c_first );
    netcode_server_update( server, current_time );
    oracle_challenge_step( "response-c-with-c-first", server );
    if ( test_script.num_packets != 8 )
        return 1;
    FILE * trace = fopen( trace_path, "wb" );
    if ( !trace )
        return 1;
    for ( int i = 0; i < test_script.num_packets; i++ )
    {
        uint32_t n = (uint32_t) test_script.packet_bytes[i];
        uint8_t size[4] = { (uint8_t) n, (uint8_t) ( n >> 8 ), (uint8_t) ( n >> 16 ), (uint8_t) ( n >> 24 ) };
        if ( fwrite( size, 1, 4, trace ) != 4 || fwrite( test_script.packet_data[i], 1, n, trace ) != n )
        {
            fclose( trace );
            return 1;
        }
    }
    if ( fclose( trace ) != 0 )
        return 1;
    netcode_server_destroy( server );
    netcode_term();
    return 0;
}

/*
    Global nonce mode.

    Starts two servers from fresh and restarts the first, and prints only
    boolean properties of the global packet sequence, never the random values:

        server-a >=2^63 <0|1>
        server-b >=2^63 <0|1>
        server-a != server-b <0|1>
        restart >=2^63 <0|1>
        restart != server-a <0|1>

    and then a client that connects with a token, disconnects, and connects
    with the same token bytes again, printing:

        client reuse <state>

    where <state> is the numeric client state (-5 = invalid connect token when
    the reused token is refused). No sockets and no wall clock: the override
    transport is used and the returned properties are independent of the
    random offsets. The field names must match the C checkout named by
    NETCODE_C_DIR; this leg is unverified without one.
*/

static struct netcode_server_t * oracle_global_server( const char * address )
{
    struct netcode_server_config_t config;
    uint8_t private_key[NETCODE_KEY_BYTES];

    memset( &config, 0, sizeof( config ) );
    oracle_private_key( private_key );
    config.protocol_id = ORACLE_PROTOCOL_ID;
    memcpy( config.private_key, private_key, NETCODE_KEY_BYTES );
    config.override_send_and_receive = 1;
    config.send_packet_override = oracle_send_override;
    config.receive_packet_override = oracle_receive_override;

    return netcode_server_create( address, &config, 0.0 );
}

static int oracle_global_main( void )
{
    struct netcode_server_t * first;
    struct netcode_server_t * second;
    uint64_t a, b, restart;

    if ( netcode_init() != NETCODE_OK )
        return 1;

    first  = oracle_global_server( "127.0.0.1:40000" );
    second = oracle_global_server( "127.0.0.1:40001" );
    if ( !first || !second )
        return 1;

    netcode_server_start( first, 1 );
    netcode_server_start( second, 1 );

    a = first->global_sequence;
    b = second->global_sequence;

    printf( "server-a >=2^63 %d\n", a >= ( 1ULL << 63 ) ? 1 : 0 );
    printf( "server-b >=2^63 %d\n", b >= ( 1ULL << 63 ) ? 1 : 0 );
    printf( "server-a != server-b %d\n", a != b ? 1 : 0 );

    netcode_server_stop( first );
    netcode_server_start( first, 1 );
    restart = first->global_sequence;

    printf( "restart >=2^63 %d\n", restart >= ( 1ULL << 63 ) ? 1 : 0 );
    printf( "restart != server-a %d\n", restart != a ? 1 : 0 );

    netcode_server_destroy( first );
    netcode_server_destroy( second );
    netcode_term();

    return 0;
}

/*
    Loopback callback mode.

    Connects a loopback client and a loopback server client with the
    send_loopback_packet_callback unset and then set, on a client and on a
    server, printing one line per attempt:

        <side> <unset|set> -> <refused|connected>

    A missing send-loopback callback must be refused in every build. No sockets
    and no wall clock: the callback is the only transport observed.
*/

struct netcode_server_t * g_loopback_server = NULL;

static int oracle_loopback_main( void )
{
    struct netcode_server_config_t sconfig;
    struct netcode_client_config_t cconfig;
    struct netcode_server_t * server;
    struct netcode_client_t * client;
    uint8_t private_key[NETCODE_KEY_BYTES];

    if ( netcode_init() != NETCODE_OK )
        return 1;

    memset( &sconfig, 0, sizeof( sconfig ) );
    oracle_private_key( private_key );
    sconfig.protocol_id = ORACLE_PROTOCOL_ID;
    memcpy( sconfig.private_key, private_key, NETCODE_KEY_BYTES );
    sconfig.override_send_and_receive = 1;
    sconfig.send_packet_override = oracle_send_override;
    sconfig.receive_packet_override = oracle_receive_override;

    server = netcode_server_create( "127.0.0.1:40000", &sconfig, 0.0 );
    if ( !server )
        return 1;
    netcode_server_start( server, 1 );

    memset( &cconfig, 0, sizeof( cconfig ) );
    client = netcode_client_create( "127.0.0.1:41000", &cconfig, 0.0 );
    if ( !client )
        return 1;

    /* server loopback client with the callback unset then set */
    printf( "server unset -> %s\n",
            netcode_server_connect_loopback_client( server, 0, 0x1111, NULL ) == NETCODE_OK ? "connected" : "refused" );
    sconfig.send_loopback_packet_callback = oracle_send_override;
    printf( "server set -> %s\n",
            netcode_server_connect_loopback_client( server, 0, 0x2222, NULL ) == NETCODE_OK ? "connected" : "refused" );

    /* client loopback with the callback unset then set */
    printf( "client unset -> %s\n",
            netcode_client_connect_loopback( client, 0, 1 ) == NETCODE_OK ? "connected" : "refused" );
    cconfig.send_loopback_packet_callback = oracle_send_override;
    printf( "client set -> %s\n",
            netcode_client_connect_loopback( client, 0, 1 ) == NETCODE_OK ? "connected" : "refused" );

    netcode_client_destroy( client );
    netcode_server_destroy( server );
    netcode_term();

    return 0;
}

int main( int argc, char ** argv )
{
    FILE * f;
    uint32_t count, i;
    uint8_t * buffer;
    struct netcode_replay_protection_t replay_protection[ORACLE_MAX_GROUPS];
    int group_seen[ORACLE_MAX_GROUPS];
    uint8_t private_key[NETCODE_KEY_BYTES];

    /* receive mode: drive the C server/client receive loops with a scripted
       override transcript. See oracle_receive_main below. */
    if ( argc == 3 && strcmp( argv[1], "receive" ) == 0 )
    {
        return oracle_receive_main( argv[2] );
    }
    if ( argc == 4 && strcmp( argv[1], "challenge" ) == 0 )
    {
        return oracle_challenge_main( argv[2], argv[3] );
    }
    if ( argc == 2 && strcmp( argv[1], "global" ) == 0 )
    {
        return oracle_global_main();
    }
    if ( argc == 2 && strcmp( argv[1], "loopback" ) == 0 )
    {
        return oracle_loopback_main();
    }

    if ( argc != 2 )
    {
        fprintf( stderr, "usage: %s [receive] inputs.bin\n", argv[0] );
        return 1;
    }

    f = fopen( argv[1], "rb" );
    if ( !f )
    {
        fprintf( stderr, "oracle: could not open %s\n", argv[1] );
        return 1;
    }

    memset( group_seen, 0, sizeof( group_seen ) );
    oracle_private_key( private_key );

    if ( netcode_init() != NETCODE_OK )
    {
        fprintf( stderr, "oracle: netcode_init failed\n" );
        return 1;
    }

    oracle_setup();

    buffer = (uint8_t*) malloc( ORACLE_MAX_INPUT_BYTES );
    if ( !buffer )
    {
        fprintf( stderr, "oracle: out of memory\n" );
        return 1;
    }

    count = read_u32( f );

    for ( i = 0; i < count; i++ )
    {
        uint32_t length = read_u32( f );
        uint32_t group;
        int accepted;
        uint64_t sequence = 0;
        uint8_t packet_type = 0;

        if ( length > ORACLE_MAX_INPUT_BYTES )
        {
            fprintf( stderr, "oracle: input %u too large (%u)\n", i, length );
            return 1;
        }

        if ( fread( buffer, 1, length, f ) != length )
        {
            fprintf( stderr, "oracle: short input %u\n", i );
            return 1;
        }

        group = read_u32( f );

        if ( group >= ORACLE_MAX_GROUPS )
        {
            fprintf( stderr, "oracle: replay group %u out of range\n", group );
            return 1;
        }

        if ( group != 0 && !group_seen[group] )
        {
            netcode_replay_protection_reset( &replay_protection[group] );
            group_seen[group] = 1;
        }
        else if ( group == 0 )
        {
            netcode_replay_protection_reset( &replay_protection[0] );
        }

        accepted = oracle_read_packet( buffer, (int) length,
                                       &replay_protection[group], &sequence,
                                       &packet_type );

        if ( accepted )
        {
            printf( "%u %u %llu %u\n", i + 1, (unsigned) packet_type,
                    (unsigned long long) sequence, length );
        }
        else
        {
            printf( "%u refused %llu %u\n", i + 1,
                    (unsigned long long) sequence, length );
        }
    }

    free( buffer );
    fclose( f );
    netcode_term();

    return 0;
}

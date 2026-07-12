/*
    Golden wire vector generator.

    Generates the binary test vectors in this directory using the C reference
    implementation of netcode (https://github.com/mas-bandwidth/netcode). The
    Go tests in wire_compat_test.go assert that this Go implementation reads
    every vector back to the same fields and re-encodes the same fields to the
    exact same bytes, proving wire compatibility with the C implementation.

    All inputs (keys, nonces, sequence numbers, timestamps, payloads) are fixed
    patterns, so the output is deterministic and any change to either
    implementation's wire format shows up as a byte diff.

    To regenerate, from the root of this repository:

        cc -O2 -I $NETCODE_C -I $NETCODE_C/sodium \
            -o generate_vectors testdata/generate_vectors.c $NETCODE_C/sodium/sodium.c
        ./generate_vectors testdata

    where $NETCODE_C is a checkout of the C implementation. The CI wire-compat
    job does exactly this against the C implementation's main branch and fails
    if the regenerated vectors differ from the ones committed here.
*/

#include "netcode.c"

#include <stdio.h>
#include <stdlib.h>

// fixed fixture values. these are mirrored in wire_compat_test.go and must not change.

#define FIXTURE_PROTOCOL_ID         0x1122334455667788ULL
#define FIXTURE_CLIENT_ID           0x0102030405060708ULL
#define FIXTURE_TIMEOUT_SECONDS     15
#define FIXTURE_CREATE_TIMESTAMP    0xAABBCCDD11223300ULL
#define FIXTURE_EXPIRE_TIMESTAMP    0xAABBCCDD11223344ULL
#define FIXTURE_CHALLENGE_SEQUENCE  0xFFEEDDCCBBAA9988ULL

static void fixture_pattern( uint8_t * data, int bytes, int multiplier, int offset )
{
    int i;
    for ( i = 0; i < bytes; i++ )
    {
        data[i] = (uint8_t) ( i * multiplier + offset );
    }
}

static void fixture_packet_key( uint8_t * key )           { fixture_pattern( key, NETCODE_KEY_BYTES, 7, 1 ); }
static void fixture_private_key( uint8_t * key )          { fixture_pattern( key, NETCODE_KEY_BYTES, 11, 3 ); }
static void fixture_challenge_key( uint8_t * key )        { fixture_pattern( key, NETCODE_KEY_BYTES, 13, 5 ); }
static void fixture_client_to_server_key( uint8_t * key ) { fixture_pattern( key, NETCODE_KEY_BYTES, 3, 1 ); }
static void fixture_server_to_client_key( uint8_t * key ) { fixture_pattern( key, NETCODE_KEY_BYTES, 5, 2 ); }
static void fixture_connect_token_nonce( uint8_t * nonce ) { fixture_pattern( nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES, 17, 9 ); }

static void fixture_server_addresses( struct netcode_address_t * addresses )
{
    memset( addresses, 0, sizeof( struct netcode_address_t ) * 3 );

    addresses[0].type = NETCODE_ADDRESS_IPV4;
    addresses[0].data.ipv4[0] = 127;
    addresses[0].data.ipv4[1] = 0;
    addresses[0].data.ipv4[2] = 0;
    addresses[0].data.ipv4[3] = 1;
    addresses[0].port = 40000;

    addresses[1].type = NETCODE_ADDRESS_IPV6;
    addresses[1].data.ipv6[0] = 0xfe80;
    addresses[1].data.ipv6[4] = 0x0202;
    addresses[1].data.ipv6[5] = 0xb3ff;
    addresses[1].data.ipv6[6] = 0xfe1e;
    addresses[1].data.ipv6[7] = 0x8329;
    addresses[1].port = 50000;

    addresses[2].type = NETCODE_ADDRESS_IPV4;
    addresses[2].data.ipv4[0] = 10;
    addresses[2].data.ipv4[1] = 24;
    addresses[2].data.ipv4[2] = 93;
    addresses[2].data.ipv4[3] = 7;
    addresses[2].port = 12345;
}

static const char * output_directory;

static void write_vector( const char * name, const uint8_t * data, int bytes )
{
    char path[1024];
    snprintf( path, sizeof( path ), "%s/%s", output_directory, name );
    FILE * file = fopen( path, "wb" );
    if ( !file )
    {
        printf( "error: could not open %s for writing\n", path );
        exit( 1 );
    }
    if ( fwrite( data, 1, bytes, file ) != (size_t) bytes )
    {
        printf( "error: could not write %s\n", path );
        exit( 1 );
    }
    fclose( file );
    printf( "wrote %s (%d bytes)\n", path, bytes );
}

int main( int argc, char ** argv )
{
    if ( argc != 2 )
    {
        printf( "usage: generate_vectors <output directory>\n" );
        return 1;
    }

    output_directory = argv[1];

    if ( netcode_init() != NETCODE_OK )
    {
        printf( "error: failed to initialize netcode\n" );
        return 1;
    }

    uint8_t packet_key[NETCODE_KEY_BYTES];
    uint8_t private_key[NETCODE_KEY_BYTES];
    uint8_t challenge_key[NETCODE_KEY_BYTES];
    uint8_t connect_token_nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];

    fixture_packet_key( packet_key );
    fixture_private_key( private_key );
    fixture_challenge_key( challenge_key );
    fixture_connect_token_nonce( connect_token_nonce );

    // private connect token: plaintext and encrypted

    struct netcode_connect_token_private_t connect_token_private;
    memset( &connect_token_private, 0, sizeof( connect_token_private ) );
    connect_token_private.client_id = FIXTURE_CLIENT_ID;
    connect_token_private.timeout_seconds = FIXTURE_TIMEOUT_SECONDS;
    connect_token_private.num_server_addresses = 3;
    fixture_server_addresses( connect_token_private.server_addresses );
    fixture_client_to_server_key( connect_token_private.client_to_server_key );
    fixture_server_to_client_key( connect_token_private.server_to_client_key );
    fixture_pattern( connect_token_private.user_data, NETCODE_USER_DATA_BYTES, 7, 13 );

    uint8_t connect_token_private_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    netcode_write_connect_token_private( &connect_token_private, connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    write_vector( "connect_token_private.bin", connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    uint8_t encrypted_connect_token_private_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    memcpy( encrypted_connect_token_private_data, connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    if ( netcode_encrypt_connect_token_private( encrypted_connect_token_private_data,
                                                NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                NETCODE_VERSION_INFO,
                                                FIXTURE_PROTOCOL_ID,
                                                FIXTURE_EXPIRE_TIMESTAMP,
                                                connect_token_nonce,
                                                private_key ) != NETCODE_OK )
    {
        printf( "error: failed to encrypt private connect token\n" );
        return 1;
    }
    write_vector( "connect_token_private_encrypted.bin", encrypted_connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    // public connect token wrapping the encrypted private connect token

    struct netcode_connect_token_t connect_token;
    memset( &connect_token, 0, sizeof( connect_token ) );
    memcpy( connect_token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    connect_token.protocol_id = FIXTURE_PROTOCOL_ID;
    connect_token.create_timestamp = FIXTURE_CREATE_TIMESTAMP;
    connect_token.expire_timestamp = FIXTURE_EXPIRE_TIMESTAMP;
    memcpy( connect_token.nonce, connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( connect_token.private_data, encrypted_connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    connect_token.timeout_seconds = FIXTURE_TIMEOUT_SECONDS;
    connect_token.num_server_addresses = 3;
    fixture_server_addresses( connect_token.server_addresses );
    fixture_client_to_server_key( connect_token.client_to_server_key );
    fixture_server_to_client_key( connect_token.server_to_client_key );

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_write_connect_token( &connect_token, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );
    write_vector( "connect_token.bin", connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    // challenge token: plaintext and encrypted

    struct netcode_challenge_token_t challenge_token;
    memset( &challenge_token, 0, sizeof( challenge_token ) );
    challenge_token.client_id = FIXTURE_CLIENT_ID;
    fixture_pattern( challenge_token.user_data, NETCODE_USER_DATA_BYTES, 9, 17 );

    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
    netcode_write_challenge_token( &challenge_token, challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
    write_vector( "challenge_token.bin", challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    uint8_t encrypted_challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
    memcpy( encrypted_challenge_token_data, challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
    if ( netcode_encrypt_challenge_token( encrypted_challenge_token_data,
                                          NETCODE_CHALLENGE_TOKEN_BYTES,
                                          FIXTURE_CHALLENGE_SEQUENCE,
                                          challenge_key ) != NETCODE_OK )
    {
        printf( "error: failed to encrypt challenge token\n" );
        return 1;
    }
    write_vector( "challenge_token_encrypted.bin", encrypted_challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // packets, one of each type, with varied sequence numbers to cover the
    // variable length sequence encoding

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];
    int bytes_written;

    {
        struct netcode_connection_request_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        packet.protocol_id = FIXTURE_PROTOCOL_ID;
        packet.connect_token_expire_timestamp = FIXTURE_EXPIRE_TIMESTAMP;
        memcpy( packet.connect_token_nonce, connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        memcpy( packet.connect_token_data, encrypted_connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_request.bin", buffer, bytes_written );
    }

    {
        struct netcode_connection_denied_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x11ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_denied.bin", buffer, bytes_written );
    }

    {
        struct netcode_connection_challenge_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
        packet.challenge_token_sequence = FIXTURE_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, encrypted_challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x2233ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_challenge.bin", buffer, bytes_written );
    }

    {
        struct netcode_connection_response_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
        packet.challenge_token_sequence = FIXTURE_CHALLENGE_SEQUENCE;
        memcpy( packet.challenge_token_data, encrypted_challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x334455ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_response.bin", buffer, bytes_written );
    }

    {
        struct netcode_connection_keep_alive_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
        packet.client_index = 10;
        packet.max_clients = 16;
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x44556677ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_keep_alive.bin", buffer, bytes_written );
    }

    {
        uint8_t payload_buffer[sizeof( struct netcode_connection_payload_packet_t ) + NETCODE_MAX_PAYLOAD_BYTES];
        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) payload_buffer;
        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = NETCODE_MAX_PAYLOAD_BYTES;
        fixture_pattern( packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES, 23, 11 );
        bytes_written = netcode_write_packet( packet, buffer, sizeof( buffer ), 0x123456789ABCDEF0ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_payload.bin", buffer, bytes_written );
    }

    {
        struct netcode_connection_disconnect_packet_t packet;
        packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
        bytes_written = netcode_write_packet( &packet, buffer, sizeof( buffer ), 0x556677889900ULL, packet_key, FIXTURE_PROTOCOL_ID );
        write_vector( "packet_connection_disconnect.bin", buffer, bytes_written );
    }

    netcode_term();

    return 0;
}

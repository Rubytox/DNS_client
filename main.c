#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_LENGTH  8192
#define MAXLINE     1000
#define DNS_PACKET_MAX_SIZE     512

// To remove warning
char *strdup(const char *);

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

typedef struct {
    uint8_t QR : 1;
    uint8_t OPCODE : 4;
    uint8_t AA : 1;
    uint8_t TC : 1;
    uint8_t RD : 1;
    uint8_t RA : 1;
    uint8_t Z : 1;
    uint8_t RCODE : 4;
} DNS_HEADER_FLAGS;

typedef struct {
    uint16_t identification;
    DNS_HEADER_FLAGS flags;
    uint16_t nb_questions;
    uint16_t nb_answers;
    uint16_t nb_RR;
    uint16_t nb_additional_RR;
} DNS_HEADER;

typedef struct {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
} DNS_QUESTION;

typedef struct {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
    uint16_t ttl[2];
    uint16_t rdlength;
    uint16_t *rdata;  // Of length rdlength
} DNS_ANSWER;

typedef struct {
    DNS_HEADER header;
    DNS_QUESTION question;
    DNS_ANSWER answer;
} DNS_PACKET;


void set_query(DNS_HEADER *header)
{
    header->flags.QR = 0;
}

void set_answer(DNS_HEADER *header)
{
    header->flags.QR = 1;
}

typedef enum {
    QUERY = 0,
    IQUERY,
    STATUS
} OPCODE;

void set_opcode(DNS_HEADER *header, OPCODE opcode)
{
    header->flags.OPCODE = opcode;
}

void set_RD(DNS_HEADER *header)
{
    header->flags.RD = 1;
}

/**
 * Returns a pointer to a memory area containing the packet
 * as a contiguous area
 */
void *get_query_blob(DNS_PACKET *packet, int name_length)
{
    int header_size = sizeof(packet->header);
    int question_size = 2 * sizeof(uint16_t) + name_length * sizeof(uint8_t);

    void *blob = calloc(header_size + question_size, sizeof(uint8_t));
    uint8_t offset = 0;
    memcpy(blob, &(packet->header), header_size * sizeof(uint8_t)); // Copy header
    offset += header_size;
    memcpy(blob + offset, packet->question.name, name_length * sizeof(uint8_t));
    offset += name_length;
    *((uint8_t *) blob + offset) = packet->question.type & 0xFF;    // LSB
    *((uint8_t *) blob + offset + 1) = packet->question.type >> 8;  // MSB
    *((uint8_t *) blob + offset + 2) = packet->question.class & 0xFF;
    *((uint8_t *) blob + offset + 3) = packet->question.class >> 8;

    return blob;
}

DNS_PACKET *get_response_blob(void *blob, int name_length)
{
    DNS_PACKET *res = calloc(1, sizeof(DNS_PACKET));
    
    int offset = 0;
    uint8_t *blob_8 = (uint8_t *) blob;

    memcpy(res, blob, sizeof(DNS_HEADER));
    offset += sizeof(DNS_HEADER);
    
    // TODO: here check how many answers we have and realloc if needed

    // Alloc name and copy name
    res->question.name = calloc(name_length, sizeof(uint8_t));
    memcpy(res->question.name, blob + offset, name_length * sizeof(uint8_t));
    offset += name_length;

    // Copy type and class
    res->question.type = *(blob_8 + offset) | (*(blob_8 + offset + 1) << 8);  // MSB||LSB
    res->question.class = *(blob_8 + offset + 2) | (*(blob_8 + offset + 3) << 8);  // MSB||LSB

    // Fill answer
    res->answer.name = calloc(name_length, sizeof(uint8_t));
    memcpy(res->answer.name, res->question.name, name_length * sizeof(uint8_t)); // Cheating but ok :)



    return res;
}

char *DNS_A(char *domain_name)
{
    struct protoent *udp = getprotobyname("udp");
    int socket_desc = socket(AF_INET, SOCK_DGRAM, udp->p_proto);
    /* free(udp); */

    if (socket_desc < 0) {
        printf("Could not create socket\n");
        return NULL;
    }

    sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    sa.sin_addr.s_addr = inet_addr("8.8.8.8");

    int res = connect(socket_desc, (sockaddr *) &sa, sizeof(sa));
    if (res < 0) {
        printf("Could not connect to 8.8.8.8:53\n");
        return NULL;
    }

    DNS_PACKET query = { 0 };
    set_answer(&query.header);
    set_opcode(&query.header, QUERY);
    query.header.identification = htons(1337);
    query.header.nb_questions = htons(1);

    // Compute length of question name
    char *iter = strdup(domain_name);
    char *to_free = iter;

    int length = 0;
    char *segment = strtok(iter, ".");
    while (segment) {
        int segment_length = strlen(segment);
        printf("segment: %s [len: %d]\n", segment, segment_length);
        length += 1 + segment_length; // 1 byte for length
        segment = strtok(NULL, ".");
    }
    length++; // Don't forget NULL byte at the end!!

    query.question.name = calloc(length, sizeof(uint8_t));
    printf("domain: %s\n", domain_name);
    printf("malloc of: %d bytes\n", length);
    free(to_free);

    iter = strdup(domain_name);
    to_free = iter;
    segment = strtok(iter, ".");
    int current_byte = 0;
    while (segment) {
        uint8_t segment_length = strlen(segment);

        query.question.name[current_byte++] = segment_length;
        for (int i = 0; i < segment_length; i++)
            query.question.name[current_byte++] = segment[i];

        segment = strtok(NULL, ".");
    }

    free(to_free);

    query.question.type = htons(1); // A
    query.question.class = htons(1); // IN

    /* int blob_size = sizeof(query) - sizeof(uint8_t *) + length * sizeof(uint8_t); */
    int blob_size = sizeof(query.header) + length * sizeof(uint8_t) + 2 * sizeof(uint16_t);
    void *blob = get_query_blob(&query, length);
    sendto(socket_desc, blob, blob_size, 0, (sockaddr *) NULL, sizeof(sa));
    free(blob);
    

    uint8_t *resp_blob = calloc(DNS_PACKET_MAX_SIZE, sizeof(uint8_t));

    recvfrom(socket_desc, resp_blob, DNS_PACKET_MAX_SIZE * sizeof(uint8_t), 0, (sockaddr *) NULL, NULL);

    DNS_PACKET *response = get_response_blob(resp_blob, length);
    free(response);

    free(query.question.name);
    free(resp_blob);
}

int get(char *IP, int port, char *host, char *path)
{
    char client_message[MAX_LENGTH] = { 0 };

    strcat(client_message, "GET ");
    strncat(client_message, path, strlen(path));
    strcat(client_message, " HTTP/1.1\r\nHost: ");
    strncat(client_message, host, strlen(host));
    strcat(client_message, "\r\n\r\n");


    int socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc < 0) {
        printf("Could not create socket\n");
        return -1;
    }
    printf("Socket created\n");

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(IP);
    
    int res = connect(socket_desc, (sockaddr *) &server_addr, sizeof(server_addr));
    if (res < 0) {
        char ip[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, &(server_addr.sin_addr), ip, INET_ADDRSTRLEN);
        printf("Could not connect to port %s:%d\n", ip, server_addr.sin_port);
        return -1;
    }

    res = send(socket_desc, client_message, strlen(client_message), 0);
    if (res < 0) {
        printf("Could not send message\n");
        return -1;
    }

    char server_message[MAX_LENGTH] = { 0 };
    res = recv(socket_desc, server_message, sizeof(server_message), MSG_WAITALL);
    if (res < 0) {
        printf("Could not receive message\n");
        return -1;
    }

    printf("Request:\n");
    char *line = strtok(client_message, "\r\n");
    printf(">\n");
    while (line) {
        printf(" | %s\n", line);
        line = strtok(NULL, "\r\n");
    }
    printf(" *\n");
    printf("==============================================\n");

    printf("Response:\n");
    line = strtok(server_message, "\r\n");
    printf(">\n");
    while (line) {
        printf(" | %s\n", line);
        line = strtok(NULL, "\r\n");
    }
    printf(" *\n");

    close(socket_desc);

    return 0;
}

int main(int argc, char *argv[])
{
    /* get("15.236.18.242", 80, "www.test.com", "/"); */

    DNS_A("www.google.com");

    return 0;
}

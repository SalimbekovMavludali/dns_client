#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#define packed __attribute__((packed))

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;
typedef unsigned long long int int64;

#define $v (void *)
#define $c (char *)
#define $i (int)
#define $1 (int8 *)
#define $2 (int16)
#define $4 (int32)
#define $8 (int64)

struct s_packet {
    struct {
        int8 dst[6];
        int8 src[6];
        int16 type;
    } e packed;

    struct {
        int8 ihl:4;
        int8 ver:4;
        int8 ecn:2;
        int8 dscp:6;
        int16 length;
        int16 id;
        int16 offset:13;
        int8 flags:3;
        int8 ttl;
        int8 protocol;
        int16 checksum;
        int32 src;
        int32 dst;
    } i packed;

    struct {
        int16 src;
        int16 dst;
        int16 length;
        int16 checksum;
    } u packed;

    struct {
        int16 id;
        bool rd:1;
        bool tc:1;
        bool aa:1;
        int8 opcode:4;
        bool qr:1;
        int8 rcode:4;
        bool cd:1;
        bool ad:1;
        bool z:1;
        bool ra:1;
        struct {
            int16 questions;
            int16 answers;
            int16 authrrs;
            int16 additionalrrs;
        } num packed;
    } d packed;
} packed;

typedef struct s_packet packet;

void zero(int8*,int16);

// constructors
packet *mkpacket(...);

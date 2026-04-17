#include <dnscli.h>

void zero(int8 *dst, int16 size) {
    int16 n;
    int8 *p;

    for (p=dst, n=size; n; n--, p++)
        *p = 0;
    
    return;
}

packet *mkpacket(...) {
    int16 size;
    packet *p;
    packet pkt;

    pkt = (packet){
        .e {
            .dst = $1 "",
            .src = $1 "",
            .type = 0xaabb;
        }
    };

    size = sizeof(struct s_packet);
    p = (packet *)alloc(size);
    assert(p);
    zero($1 p, size);
    *p = pkt;

    // ...

    return p;
}

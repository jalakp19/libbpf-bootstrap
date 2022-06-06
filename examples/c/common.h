#ifndef __COMMON_H
#define __COMMON_H

struct sip_msg {
    int flag;
    int fd;
    int len;
    char comm[20];
    char msg[500];
};

#endif /* __COMMON_H */
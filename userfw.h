/*headers*/
#include <linux/types.h>

struct fw_rule_struct {
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    unsigned int in;
    unsigned int proto;
    char action;  //NONE=0; ADD=1; REMOVE=2; VIEW=3
}
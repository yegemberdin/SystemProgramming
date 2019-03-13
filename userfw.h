
/*headers*/
#include <linux/types.h>

<<<<<<< HEAD
<<<<<<< HEAD
struct fw_rule_struct {
=======
struct mfw_rule_struct {
>>>>>>> 6231ac6801319c4826db1fa43aa6d5e22792a24e
=======
struct fw_rule_struct {
>>>>>>> 1639b22a5daee076f37a809f90a6f3793bb741ba
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    unsigned int in;
    unsigned int proto;
    char action;  //NONE=0; ADD=1; REMOVE=2; VIEW=3
}



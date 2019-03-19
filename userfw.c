#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>


#include "userfw.h"

//function, which sends rules from user space to kernel module via writting them to device file

static void send_rule(struct fw_rule_struct *fw_rule)
{
    FILE *fp;
    fp = fopen("/proc/firewallFile", "w");
    if (fp == NULL) {
        printf("device file open error");
        exit(1);
    } else {
        fwrite(fw_rule, sizeof(*fw_rule), 1, fp);
    }
    fclose(fp);

   
}

static void get_a_rule(struct fw_rule_struct * rule)
{
	struct in_addr in;
    
    printf("in_out: %-3s\n", rule->in? "In": "Out");
    in.src_ip=rule->src_ip;
    printf("src_ip: %-15s\n", inet_ntoa(in));
    printf("src_port: %-5d\n", ntohs(rule->src_port));
    in.dest_ip=rule->dest_ip;
    printf("dest_ip: %-15s\n", inet_ntoa(in));
    printf("dest_port: %-5d\n", ntohs(rule->dest_port));
    printf("proto: %d\n", rule->proto);
    printf("action: %d\n", rule->action);
}

static void get_rules()
{
	struct fw_rule_struct * rules;
    FILE *fp;
    fp = fopen("/proc/firewallFile", "r");
    if (fp == NULL) {
        printf("device file open error");
        exit(1);
    }
    int byte_count; 
    int count = 1;
    while (byte_count=fread(&rules, sizeof(struct fw_rule_struct), 1, fp) > 0) {
        printf("rule number %d : \n", count++);
        get_a_rule(&rules);
        putchar('\n');
    }
}

static int parsing(int argc, char **argv, struct fw_rule_struct *fw_ret_rule){
	
	struct fw_rule_struct fw_rule = {};
	struct in_addr in;
	int c = 0;

	    char *optString = "iogads:p:t:q:c:";
	     struct option long_options[] = {
	     	     	{"in", no_argument, 0, 'i'},
                    {"out", no_argument, 0, 'o'},
	     	        {"print", no_argument, 0, 'g'},
	     	        {"add", no_argument, 0, 'a'},
	     	        {"delete", required_argument, 0, 'd'},
                    {"srcip", required_argument, 0, 's'},
                    {"srcport", required_argument, 0, 'p'},
                    {"destip", required_argument, 0, 't'},
                    {"destport", required_argument, 0, 'q'},
                    {"proto", required_argument, 0, 'c'},                 
        		    {0, 0, 0, 0}
        		};
    fw_rule.action=0;
    while (1) {
        c = getopt_long(argc, argv, optString, long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        
        case 'i':	
			if(fw_rule.in == 0) {
				printf("Select In or Out\n");
				return -1;
			}
			fw_rule.in = 1;
			break;
		case 'o':
			if(fw_rule.in == 1) {
				printf("Select In or Out\n");
				return -1;
			}
			fw_rule.in = 0;			
			break;
		case 'g':	
			
			fw_rule.action =3;
			break;	
		case 'a':
			
			fw_rule.action =1;
			break;
		case 'd':	
			fw_rule.action =2;
			break;
		case 's':	
			if(inet_aton(optarg, &in) == 0) {
				printf("Not correct source ip address\n");
				return -1;
			}
			fw_rule.src_ip = in.s_addr;
			break;
		case 'p':
     		fw_rule.src_port = (unsigned int)atoi(optarg);	
			break;	
		case 't':	
			if(inet_aton(optarg, &in) == 0) {
				printf("Not correct dest ip address\n");
				return -1;
			}
			fw_rule.dest_ip = in.s_addr;
			break;
		case 'q':
     		fw_rule.dest_port = (unsigned int)atoi(optarg);	
			break;	
		case 'с':
     		fw_rule.proto = (unsigned int)atoi(optarg);	
			break;		
	    }
	}	
	if(fw_rule.action == 0) {
		printf("Please specify action --(print|add|delete)\n");
		return -1;
	}
	*fw_ret_rule=fw_rule;

	return 0;
}

int main(int argc, char *argv[])
{
	struct fw_rule_struct fw_rule = {};
	int ret;

	ret = parsing(argc, argv, &fw_rule);
	if(ret < 0)
		return ret;

	switch(fw_rule.action) {
	case 1:
	case 2:
		send_rule(&fw_rule);
		get_a_rule(&fw_rule);
		break;
	case 3:
		get_rules();
		break;
	default:
		return 0;
	}
}









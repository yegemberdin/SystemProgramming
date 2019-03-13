#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "userfw.h"

//function, which sends rules from user space to kernel module via writting them to device file

void send_rule(struct fw_rule_struct *fw_rule)
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

void get_a_rule(struct fw_rule_struct * rule)
{
	struct in_addr in
    
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

void get_rules()
{
	struct fw_rule_struct * rules
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
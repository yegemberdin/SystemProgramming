#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>//file operations
#include <linux/slab.h>
#include <asm/uaccess.h>//put_user
#include <linux/list.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>//for skb
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DEVICE_INTF_NAME "firewallFile" 
#define DEVICE_MAJOR_NUM 100  

MODULE_LICENSE("GPL");

typedef struct fw_rule_struct {
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    unsigned int in;
    unsigned int proto;
    char action;  //NONE=0; ADD=1; REMOVE=2; VIEW=3
    struct list_head list;
} fw_rule;
static fw_rule rule_list;

struct list_head In_lhead;	//headers for out-in lists
struct list_head Out_lhead;	




static int Device_open; /* Opening counter of a device file */
static char *Buffer;	/* A buffer for receving data from a user space */


//general check filter

static unsigned int fw_check_filter(void *priv, struct sk_buff *skb,
	       const struct nf_hook_state *state,
	       struct list_head *rule_list_head)
{
	
	fw_rule *r;
	struct iphdr *iph= (struct iphdr *)skb_network_header(skb);//socket buffer
	struct udphdr *udp_header;
        struct tcphdr *tcp_header;
	unsigned int src_ip = ip_header->saddr;
        unsigned int dest_ip = ip_header->daddr;
	unsigned int src_port;
	unsigned int dest_port;
        struct list_head *listh;
	src_ip = iph->saddr;
	dest_ip = iph->daddr;
	if(iph->protocol == 17) {
		udp_header = (struct udphdr *)(skb_transport_header(skb));
                src_port = (unsigned int)udp_header->source;
                dest_port = (unsigned int)udp_header->dest;
		
	}
	else if(iph->protocol == 6) {
		tcp_header = (struct tcphdr *)(skb_transport_header(skb));
                src_port = (unsigned int)tcp_header->source;
                dest_port = (unsigned int)tcp_header->dest;
	}
	else
		return NF_ACCEPT;//netfilter accept

	/* Loop through the rule list and perform exact match */
        int rule_num = 0;
	listh = rule_list_head;
	list_for_each_entry(r, listh, list) {
                rule_num++;
                printk(KERN_INFO "rule number %d check \n", rule_num);

		if((r->proto==1) && (r->proto != iph->protocol))
			continue;

		if(r->src_ip==1)
			continue;

		if(r->src_port==1) && (r->src_port != src_port))
			continue;

		if(r->dest_ip==1)
			continue;

		if(r->dest_port==1) && (r->dest_port != dest_port))
			continue;

		if (r->action == 1) {//delete info
                   printk(KERN_INFO "rule number %d match: block\n", rule_num);
                   return NF_DROP;//add info
                } else if (r->action == 0) {
                   printk(KERN_INFO "rule number %d match: log\n", rule_num);
                   printk(KERN_INFO "\n");
                   return NF_ACCEPT;
        }
    
        printk(KERN_INFO "\n");
        return NF_ACCEPT;
}

//filter for all packets
static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return fw_check_filter(priv, skb, state, &In_lhead);
}


static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return fw_check_filter(priv, skb, state, &Out_lhead);
}



/*
 * The function handles user-space view operation, which reads inbound and
 * outbound rules stored in the module. The function is called iteratively
 * until it returns 0.
 */

static ssize_t fw_dev_read(struct file *file, char *buffer, size_t length, loff_t *f_pos//The current reading or writing position.)
{
	
	static struct list_head *inlp = &In_lhead;
	static struct list_head *outlp = &Out_lhead;
	struct rule_node *node;
	char *readptr;
        int byte_read = 0;

	//Reading lules if it is not the last one in the inbound and outbound lists
	if(inlp->next != &In_lhead) {
		node = list_entry(inlp->next, struct rule_node, list);
		readptr = (char*)&node->rule;
		inlp = inlp->next;
	}
	else if(outlp->next != &Out_lhead) {
		node = list_entry(outlp->next, struct rule_node, list);
		readptr = (char*)&node->rule;
		outlp = outlp->next;
	}

	else {
		inlp = &In_lhead;
		outlp = &Out_lhead;
		return 0;
	}

	//getting access to user space
	while(length && (byte_read < sizeof(struct fw_rule_struct))) {
		put_user(readptr[byte_read], &(buffer[byte_read]));
		byte_read++;
		length--;
	}
	return byte_read;
}


void ip_hl_to_str(unsigned int ip, char *ip_str)
{
    /*convert hl to byte array first*/
    unsigned char ip_arr[4];
    memset(ip_arr, 0, 4);
    ip_arr[0] = (ip_arr[0] | (ip >> 24));
    ip_arr[1] = (ip_arr[1] | (ip >> 16));
    ip_arr[2] = (ip_arr[2] | (ip >> 8));
    ip_arr[3] = (ip_arr[3] | ip);
    sprintf(ip_str, "%u.%u.%u.%u", ip_arr[0], ip_arr[1], ip_arr[2], ip_arr[3]);
}

 // The function adds a rule to either an inbound list or an outbound list.


void print_a_rule(fw_rule* rule)
{
    char src_ip[16], dest_ip[16];
    ip_hl_to_str(rule->src_ip, src_ip);
    ip_hl_to_str(rule->dest_ip, dest_ip);

    printk(KERN_INFO "in_out: %-3s\n", rule->in? "In": "Out"));
    printk(KERN_INFO "src_ip: %s\n", src_ip);
    printk(KERN_INFO "src_port: %d\n", rule->src_port);
    printk(KERN_INFO "dest_ip: %s\n", dest_ip);
    printk(KERN_INFO "dest_port: %d\n", rule->dest_port);
    printk(KERN_INFO "proto: %d\n", rule->proto);
    printk(KERN_INFO "action: %d\n", rule->action);
}

static void delete_a_rule(unsigned int num)
{
    struct list_head *p, *q;
    fw_rule *a_rule;
    printk(KERN_INFO "delete a rule: %d\n", num);
    list_for_each_safe(p, q, &rule_list.list) {
        num--;
        if (num == 0) {
            a_rule = list_entry(p, fw_rule, list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}


//operations from user space module to kernel

static ssize_t fw_dev_write(struct file *file, const char *buffer, size_t length,loff_t *offset)
{
	fw_rule *ctlp;
	int byte_write = 0;

	if(length < sizeof(*ctlp)) {
		printk(KERN_ALERT
		       "Firewall: Receives incomplete instruction\n");
		return byte_write;
	}

	/* Transfer user-space data to kernel-space buffer */
	while(length && (byte_write < sizeof(*ctlp))) {

		get_user(Buffer[byte_write], buffer + byte_write);
		byte_write++;
		length--;
	}


	switch(ctlp.action) {
	case 1:
		print_a_rule(ctlp);
		break;
	case 2:
		delete_a_rule(ctlp);
		break;
	default:
		printk(KERN_ALERT
		       "Firewall: Received an unknown command\n");
	}

	return byte_write;
}


//hook configurations for netfilter
struct nf_hook_ops fw_in_hook_ops = {
	.hook = hook_func_in,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};


struct nf_hook_ops fw_out_hook_ops = {
	.hook = hook_func_out,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};


//File operation configuration for a device file 
struct file_operations fw_dev_fops = {
	.read = fw_dev_read,
	.write = fw_dev_write,
        .owner	= THIS_MODULE,
};



static int __init fw_mod_init(void)
{
	int ret;	

	Buffer = (char *)kmalloc(sizeof(struct fw_rule *), GFP_KERNEL);
	if(Buffer == NULL) {
		printk(KERN_ALERT
		       "Firewall: Fails to start due to out of memory\n");
		return -1;
	}
	INIT_LIST_HEAD(&In_lhead);
	INIT_LIST_HEAD(&Out_lhead);

	/* Register character device */
	ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &fw_dev_fops);
	if(ret < 0) {
		printk(KERN_ALERT
		       "Firewall: Fails to start due to device register\n");
		return ret;
	}
	printk(KERN_INFO "Firewall: "
	       "Char device %s is registered with major number %d\n",
	       DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);
	printk(KERN_INFO "Firewall: "
	       "To communicate to the device, use: mknod %s c %d 0\n",
	       DEVICE_INTF_NAME, DEVICE_MAJOR_NUM);

        //register hook options
	nf_register_hook(&fw_in_hook_ops);
	nf_register_hook(&fw_out_hook_ops);
	return 0;
}

module_init(fw_mod_init);



static void __exit fw_mod_cleanup(void)
{
	struct rule_node *nodep;
	struct rule_node *ntmp;

	kfree(Buffer);

	list_for_each_entry_safe(nodep, ntmp, &In_lhead, list) {
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Firewall: Deleted inbound rule %p\n",
		       nodep);
	}

	list_for_each_entry_safe(nodep, ntmp, &Out_lhead, list) {
		list_del(&nodep->list);
		kfree(nodep);
		printk(KERN_INFO "Firewall: Deleted outbound rule %p\n",
		       nodep);
	}

	unregister_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME);
	printk(KERN_INFO "Firewall: Device %s is unregistered\n",
	       DEVICE_INTF_NAME);

	nf_unregister_hook(&fw_in_hook_ops);
	nf_unregister_hook(&fw_out_hook_ops);
}
module_exit(fw_mod_cleanup);

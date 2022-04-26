#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/string.h>

atomic_t pre_count = ATOMIC_INIT(0);
atomic_t post_count = ATOMIC_INIT(0);
atomic_t context_switch_count = ATOMIC_INIT(0);

DEFINE_SPINLOCK(my_lock);

struct my_struct{
	struct task_struct *prev;
};


// Hashtable
DEFINE_HASHTABLE(my_hashtable,20);

struct my_hash_linklist {
	int pid;
	unsigned long long start_time;
	struct hlist_node hash_linklist;
};

static void insert_hash (int pid, unsigned long long start_time ){
	struct my_hash_linklist *hash_list = kmalloc(sizeof(*hash_list), GFP_ATOMIC);
	hash_list->pid = pid;
	hash_list->start_time = start_time;
	hash_add(my_hashtable,&hash_list->hash_linklist,hash_list->pid);
}

static unsigned long long search_hash(int pid){
	struct my_hash_linklist *current_hash_linklist;
	hash_for_each_possible(my_hashtable,current_hash_linklist,hash_linklist,pid){
		if (current_hash_linklist->pid == pid){
			return current_hash_linklist->start_time;
		}
	}
	return 0;
}

static void delete_hash(int pid){
	struct my_hash_linklist *current_hash_linklist;
	int bucket;
	struct hlist_node *temp;
	hash_for_each_safe(my_hashtable, bucket, temp, current_hash_linklist, hash_linklist){
		if(current_hash_linklist->pid == pid){
			hash_del(&current_hash_linklist->hash_linklist);
			kfree(current_hash_linklist);
		}
	}
}

static void delete_hash_all(void){
	struct my_hash_linklist *current_hash_linklist;
	int bucket;
	struct hlist_node *temp;
	hash_for_each_safe(my_hashtable, bucket, temp, current_hash_linklist, hash_linklist){
		hash_del(&current_hash_linklist->hash_linklist);
		kfree(current_hash_linklist);
	}
}

// Red Black Tree
struct rb_root my_rb_root = RB_ROOT;

struct my_rbtree{
	int pid;
	unsigned long long total_time;
	struct rb_node my_rb_node;
};

static void insert_rbtree(struct rb_root *my_rb_root, int pid, unsigned long long total_time){
	struct my_rbtree *rbtree = kmalloc(sizeof(*rbtree), GFP_ATOMIC);
	struct my_rbtree *temp;
	struct rb_node **link = &(my_rb_root->rb_node);
	struct rb_node *parent = NULL;
	
	rbtree->pid = pid;
	rbtree->total_time = total_time;

	while (*link){
		parent = *link;
		temp = rb_entry(parent, struct my_rbtree, my_rb_node);
		
		if (total_time < temp->total_time){
			link = &parent->rb_left;
		}
		else{
			link = &parent->rb_right;
		}
	}
	rb_link_node(&rbtree->my_rb_node, parent, link);
	rb_insert_color(&rbtree->my_rb_node, my_rb_root);
}

static unsigned long long search_rbtree(struct rb_root *my_rb_root, int pid){
	struct rb_node *node;
    	for (node = rb_first(my_rb_root); node; node = rb_next(node)) {
      		struct my_rbtree *temp = rb_entry(node, struct my_rbtree, my_rb_node); 
      		if (temp->pid == pid) {
        		return temp->total_time;
      		}
    	}
    	return 0;
}

static void delete_rbtree(struct rb_root *my_rb_root, int pid){
	struct rb_node *node;
    	for (node = rb_first(my_rb_root); node; node = rb_next(node)){
      		struct my_rbtree *temp = rb_entry(node, struct my_rbtree, my_rb_node); 
      		if (temp->pid == pid) {
        		rb_erase(&(temp->my_rb_node), my_rb_root);
        		kfree(temp);
      		}
  	}	
}

static void delete_rbtree_all(struct rb_root *my_rb_root){
	struct rb_node *node;
    	for (node = rb_first(my_rb_root); node; node = rb_next(node)){
      		struct my_rbtree *temp = rb_entry(node, struct my_rbtree, my_rb_node); 
      		rb_erase(&(temp->my_rb_node), my_rb_root);
      		kfree(temp);
  	}
}

static void print_most_sched(struct rb_root *my_rb_root, struct seq_file *m) {
    	struct rb_node *node;
	struct my_rbtree *temp;
    	int count = 0;

    	if(!rb_first(my_rb_root)) {
        	printk(KERN_INFO "Root is null");
    	}
    	for (node = rb_last(my_rb_root); node; node = rb_prev(node)) {
        
        	if (count >= 10){
        		break;
        	}
        	temp = rb_entry(node, struct my_rbtree, my_rb_node);   
        	seq_printf(m, "PID = %d | Total TSC =  %llu \n", temp->pid, temp->total_time);
        	count++;
    	}
}

// Pre Handler
static int entry_pick_next_fair(struct kretprobe_instance *p, struct pt_regs *regs){
	struct my_struct *my_struct = (struct my_struct *)p->data;
	struct task_struct *prev = (struct task_struct*)(regs->si);
	
	if (my_struct != NULL){
		my_struct->prev = prev;
	}
	atomic_inc(&pre_count);
	return 0;
}

// Post Handler
static int ret_pick_next_fair(struct kretprobe_instance *p, struct pt_regs *regs){
	struct my_struct *my_struct = (struct my_struct *)p->data;
	struct task_struct *next = (struct task_struct*)(regs->ax);
	unsigned long long prev_new_total_time, curr_time, prev_start_time;
	
	if (my_struct != NULL && my_struct->prev != NULL && next != NULL && my_struct->prev != next){

		curr_time = rdtsc();
		spin_lock(&my_lock);
		prev_start_time = search_hash(my_struct->prev->pid);
		
		if(prev_start_time != 0){

			delete_hash(my_struct->prev->pid);
			prev_new_total_time = search_rbtree(&my_rb_root, my_struct->prev->pid) + (curr_time - prev_start_time);
			delete_rbtree(&my_rb_root, my_struct->prev->pid);
			insert_rbtree(&my_rb_root, my_struct->prev->pid, prev_new_total_time);
		}

		insert_hash(next->pid, curr_time);
		spin_unlock(&my_lock);
		atomic_inc(&context_switch_count);
	}
	atomic_inc(&post_count);
	return 0;
}

static struct kretprobe kretp = {
	.entry_handler = entry_pick_next_fair,
	.handler = ret_pick_next_fair,
	.data_size = sizeof(struct my_struct),
	.maxactive = 20,
};

static int perftop_proc_show(struct seq_file *m, void *v) {
  seq_printf(m, "Pre Count: %d\n",atomic_read(&pre_count));
  seq_printf(m, "Post Count: %d\n",atomic_read(&post_count));
  seq_printf(m, "Context Switch Count: %d\n",atomic_read(&context_switch_count));
  seq_printf(m, "***** 10 Most Scheduled Tasks *****\n");

  spin_lock(&my_lock);
  print_most_sched(&my_rb_root,m);
  spin_unlock(&my_lock);
  return 0;
}

static int perftop_proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, perftop_proc_show, NULL);
}

static const struct proc_ops perftop_proc_fops = {
  .proc_open = perftop_proc_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int __init perftop_init(void) {
  int register_retval;
  proc_create("perftop", 0, NULL, &perftop_proc_fops);
  hash_init(my_hashtable);
  kretp.kp.symbol_name = "pick_next_task_fair";
  register_retval = register_kretprobe(&kretp);

  if (register_retval < 0){
	printk(KERN_INFO "Kretprobe registration failed\n");
  }
  else{
  	printk(KERN_INFO "Planted Kretprobe at %s\n",kretp.kp.symbol_name);
  }
  return 0;
}

static void __exit perftop_exit(void) {
  unregister_kretprobe(&kretp);
  spin_lock(&my_lock);
  delete_hash_all();
  delete_rbtree_all(&my_rb_root);
  spin_unlock(&my_lock);
  remove_proc_entry("perftop", NULL);
}

MODULE_LICENSE("GPL");
module_init(perftop_init);
module_exit(perftop_exit);

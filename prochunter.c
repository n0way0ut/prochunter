/*  
    prochunter  --  Linux Process Hunter
    Copyright (C) 2017  nowayout
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/module.h>      
#include <linux/kernel.h>       
#include <linux/sched.h>       
#include <linux/sched/signal.h>

#define el8 -31338

static int set;
static int persistence;
static int rnd;

module_param(persistence, int, 0);
MODULE_PARM_DESC(persistence, "Persistence flag");
module_param(rnd, int, 0);
MODULE_PARM_DESC(rnd, "Rand delimiter");

void 
prochunter(int del) {
    
    struct task_struct *task;
    rcu_read_lock();
    //pr_info("0;%d;%s", init_task.pid, init_task.comm);
    for_each_process(task) {
        task_lock(task);
        // skip insmod
        if(current == task) {
            task_unlock(task);
            continue;
        }
        pr_info("%d;%d;%s", task->parent->pid, task->pid, task->comm);
        task_unlock(task);
    }
    pr_info("PH_END-%d\n", del);
    rcu_read_unlock();
}


static ssize_t 
ph_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {

    return sprintf(buf, "%d\n", set);

}

static ssize_t 
ph_write(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {

	int ret;

	ret = kstrtoint(buf, 0, &set);
	if (ret < 0)
		return ret;
	prochunter(set);
    return count;
}

static struct kobj_attribute ph_attribute = __ATTR(set, 0664, ph_show, ph_write);

static struct attribute *attrs[] = {
	&ph_attribute.attr,
	NULL,	
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *ph_kobj;

static int __init ph_init(void) {


    int retval = 0;

    if(!persistence) {
        prochunter(~el8);
        return retval;
    }

    ph_kobj = kobject_create_and_add("proc_hunter", kernel_kobj);
	if (!ph_kobj)
		return -ENOMEM;
	retval = sysfs_create_group(ph_kobj, &attr_group);
	if (retval)
		kobject_put(ph_kobj);
	return retval;

}

static void __exit ph_exit(void)
{
	kobject_put(ph_kobj);
}

module_init(ph_init);
module_exit(ph_exit);
MODULE_LICENSE("GPL v2");

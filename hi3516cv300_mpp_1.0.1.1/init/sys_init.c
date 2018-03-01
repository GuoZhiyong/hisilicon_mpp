#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <linux/of_platform.h>

#include "hi_type.h"
#include "hi_osal_init.h"

#define PHASE       32
#define COEFF_BUTT (PHASE / 2 + 1)

extern const int coefficient6_3M_a15[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_3M_a15);
extern const int coefficient4_2M_a05[COEFF_BUTT][4];
EXPORT_SYMBOL(coefficient4_2M_a05);
extern const int coefficient4_5M_a15[COEFF_BUTT][4];
EXPORT_SYMBOL(coefficient4_5M_a15);
extern const int coefficient8_lanczos2_8tap[COEFF_BUTT][8];
EXPORT_SYMBOL(coefficient8_lanczos2_8tap);
extern const int coefficient6_cubic[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_cubic);
extern const int coefficient8_2M_a05[COEFF_BUTT][8];
EXPORT_SYMBOL(coefficient8_2M_a05);
extern const int coefficient8_3M_a19[COEFF_BUTT][8];
EXPORT_SYMBOL(coefficient8_3M_a19);
extern const int coefficient6_4M_a20[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_4M_a20);
extern const int coefficient8_1_5M_a05[COEFF_BUTT][8];
EXPORT_SYMBOL(coefficient8_1_5M_a05);
extern const int coefficient8_cubic[COEFF_BUTT][8];
EXPORT_SYMBOL(coefficient8_cubic);
extern const int coefficient4_1_5M_a05[COEFF_BUTT][4];
EXPORT_SYMBOL(coefficient4_1_5M_a05);
extern const int coefficient6_2M_a05[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_2M_a05);
extern const int coefficient6_1_5M_a05[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_1_5M_a05);
extern const int coefficient4_cubic[COEFF_BUTT][4];
EXPORT_SYMBOL(coefficient4_cubic);
extern const int coefficient6_5M_a25[COEFF_BUTT][6];
EXPORT_SYMBOL(coefficient6_5M_a25);


extern int vi_vpss_online;
module_param(vi_vpss_online, int, S_IRUGO);
EXPORT_SYMBOL(vi_vpss_online);

extern char *sensor[4];

module_param_array(sensor, charp, NULL, S_IRUGO);


/*set default user mode helper path*/
#define PM_EVENT_HELPER_LEN 128
char pm_mpp_helper[PM_EVENT_HELPER_LEN] = "/root";
static struct ctl_table_header *ctl_head;

static struct ctl_table pm_mpp_ctl[] = {
	{
		.procname	= "mpp_notifier",
		.data		= &pm_mpp_helper,
		.maxlen		= PM_EVENT_HELPER_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{}
};

static struct ctl_path pm_umh_root[] = {
	{
		.procname	= "kernel",
	},
	{}
};

extern int SYS_ModInit(void);
extern void SYS_ModExit(void);

extern void  *reg_crg_base_va;
EXPORT_SYMBOL(reg_crg_base_va);
extern void  *reg_sys_base_va;
EXPORT_SYMBOL(reg_sys_base_va);
extern void  *reg_ddr0_base_va;
EXPORT_SYMBOL(reg_ddr0_base_va);
extern void  *reg_misc_base_va;
EXPORT_SYMBOL(reg_misc_base_va);

static int hi35xx_sys_probe(struct platform_device *pdev)
{
    struct resource *mem;
	struct device_node *online_node = NULL;
    const phandle *handle;
	struct device_node *np = pdev->dev.of_node;

    handle = of_get_property(np, "vi_vpss_online", NULL);
    if (handle)                                                                                                                                                               
        online_node = of_find_node_by_phandle(be32_to_cpup(handle));
	
    if (online_node)
    {
        if(osal_of_property_read_u32(online_node, "vi_vpss_online", &vi_vpss_online))
        {
            vi_vpss_online = 1;
        }
        //printk("====================sys probe, vi-vpss-online: %d.\n", vi_vpss_online);
    }
	
    mem = osal_platform_get_resource_byname(pdev, IORESOURCE_MEM, "misc");
    reg_misc_base_va = devm_ioremap_resource(&pdev->dev, mem);
    if (IS_ERR(reg_misc_base_va))
            return PTR_ERR(reg_misc_base_va);

    //printk("++++++++++ reg_crg_base_va = %p reg_sys_base_va = %p reg_ddr0_base_va = %p reg_misc_base_va = %p\n",
    //                   reg_crg_base_va,     reg_sys_base_va,     reg_ddr0_base_va,     reg_misc_base_va);

	osal_platform_get_module_param(pdev, "sensor0", charp, sensor[0]);
	osal_platform_get_module_param(pdev, "sensor1", charp, sensor[1]);

    if(HI_SUCCESS != SYS_ModInit())
    {
        return HI_FAILURE;
    }
    
    ctl_head = register_sysctl_paths(pm_umh_root, pm_mpp_ctl);
	

    return 0;
}

static int hi35xx_sys_remove(struct platform_device *pdev)
{
    unregister_sysctl_table(ctl_head);

    SYS_ModExit();

    reg_crg_base_va = NULL;
    reg_sys_base_va = NULL;
    reg_ddr0_base_va = NULL;
    reg_misc_base_va = NULL;

    return 0;
}

static const struct of_device_id hi35xx_sys_match[] = {
        { .compatible = "hisilicon,hi35xx_sys" },
        {},
};
MODULE_DEVICE_TABLE(of, hi35xx_sys_match);

static struct platform_driver hi35xx_sys_driver = {
        .probe          = hi35xx_sys_probe,
        .remove         = hi35xx_sys_remove,
        .driver         = {
                .name   = "hi35xx_sys",
                .of_match_table = hi35xx_sys_match,
        },
};


osal_module_platform_driver(hi35xx_sys_driver);

MODULE_LICENSE("Proprietary");

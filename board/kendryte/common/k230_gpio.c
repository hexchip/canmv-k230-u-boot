/* Copyright (c) 2025, Canaan Bright Sight Co., Ltd
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <asm/io.h>

#include <command.h>

#include <kendryte/k230_platform.h>

#include "k230_gpio.h"

typedef struct _kd_gpio {
    struct {
        volatile uint32_t dr; // 0x00: Write Data register
        volatile uint32_t ddr; // 0x04: Data direction register
        volatile uint32_t ctl; // 0x08: Control register
    } port[4]; /* 0x00 - 0x2C: port control registers */

    volatile uint32_t inten; /* 0x30: interrupt enable register */
    volatile uint32_t intmask; /* 0x34: interrupt mask register */
    volatile uint32_t inttype_level; /* 0x38: interrupt type level register */
    volatile uint32_t int_polarity; /* 0x3C: interrupt polarity register */
    volatile uint32_t intstatus; /* 0x40: interrupt status register */
    volatile uint32_t raw_intstatus; /* 0x44: raw interrupt status register */
    volatile uint32_t debounce; /* 0x48: debounce register */
    volatile uint32_t porta_eoi; /* 0x4C: port a end of interrupt register */

    volatile uint32_t input[4]; /* 0x50-0x5C: porta/b/c/d input */
    volatile uint32_t ls_sync; /* 0x60: level sync register */
    volatile uint32_t id_code; /* 0x64: ID code register */
    volatile uint32_t int_bothedge; /* 0x68: interrupt both-edge register */
    volatile uint32_t gpio_comp_version; /* 0x6C: GPIO component version register */
    volatile uint32_t config2; /* 0x70: configuration register 2 */
    volatile uint32_t config1; /* 0x74: configuration register 1 */
} kd_gpio_t;

static volatile kd_gpio_t* gpio_inst[2] = { (volatile kd_gpio_t*)GPIO0_BASE_ADDR, (volatile kd_gpio_t*)GPIO1_BASE_ADDR };

static inline __attribute__((always_inline)) void kd_pin_write_reg(volatile uint32_t* reg, int pin, int val)
{
    uint32_t reg_val = readl(reg);
    reg_val &= ~BIT(pin);
    if (val) {
        reg_val |= BIT(pin);
    }
    writel(reg_val, reg);
}

void kd_pin_set_ddr(int pin, int value)
{
    /* Magic pin mapping: 0-31:gpio0, 32-63:gpio1[0], 64-71:gpio1[1] */
    volatile kd_gpio_t* gpio     = gpio_inst[pin >= 32];
    uint8_t             port_idx = (pin >= 64);
    uint8_t             port_pin = pin & 0x1F;

    /* Set GPIO direction */
    volatile uint32_t* ddr = &gpio->port[port_idx].ddr;
    kd_pin_write_reg(ddr, port_pin, value);
}

uint32_t kd_pin_get_ddr(int pin)
{
    /* Magic pin mapping: 0-31:gpio0, 32-63:gpio1[0], 64-71:gpio1[1] */
    volatile kd_gpio_t* gpio     = gpio_inst[pin >= 32];
    uint8_t             port_idx = (pin >= 64);
    uint8_t             port_pin = pin & 0x1F;

    /* Set GPIO direction */
    volatile uint32_t* ddr = &gpio->port[port_idx].ddr;

    /* Read pin state */
    uint32_t input_val = readl(ddr);
    return (input_val & BIT(port_pin));
}

uint32_t kd_pin_get_dr(int pin)
{
    /* Magic pin mapping: 0-31:gpio0, 32-63:gpio1[0], 64-71:gpio1[1] */
    volatile kd_gpio_t* gpio      = gpio_inst[pin >= 32];
    uint8_t             port_idx  = (pin >= 64);
    uint8_t             port_pin  = pin & 0x1F;
    volatile uint32_t*  input_reg = &gpio->input[port_idx];

    /* Read pin state */
    uint32_t input_val = readl(input_reg);
    return (input_val & BIT(port_pin)) ? 1 : 0;
}

void kd_pin_set_dr(int pin, int value)
{
    /* Magic pin mapping: 0-31:gpio0, 32-63:gpio1[0], 64-71:gpio1[1] */
    volatile kd_gpio_t* gpio     = gpio_inst[pin >= 32];
    uint8_t             port_idx = (pin >= 64);
    uint8_t             port_pin = pin & 0x1F;

    /* Set GPIO Ouput Value */
    volatile uint32_t* dr = &gpio->port[port_idx].dr;
    kd_pin_write_reg(dr, port_pin, value);
}

/** Wrap gpio to uboot command ***********************************************/
#ifndef CONFIG_SPL_BUILD
int k230_gpio(char opt, int pin, char* value)
{
    int ret = 0;

    if (pin > 71 || pin < 0) {
        printf("Invalid pin: %d\n", pin);
        return -1;
    }

    printf("pin=%d opt=%c\n", pin, opt);

    switch (opt) {
    case 's': // set output value
        if (value == NULL) {
            printf("value is NULL\n");
            return -1;
        }
        kd_pin_set_dr(pin, *value ? 1 : 0);
        break;

    case 'g': // get input value
        if (value == NULL) {
            printf("value is NULL\n");
            return -1;
        }
        *value = kd_pin_get_dr(pin);
        break;

    case 'i': // set input direction
        kd_pin_set_ddr(pin, 0);
        break;

    case 'o': // set output direction + optional initial value
        kd_pin_set_ddr(pin, 1);
        if (value) {
            kd_pin_set_dr(pin, *value ? 1 : 0);
        }
        break;

    default:
        printf("Invalid opt: %c\n", opt);
        return -1;
    }

    printf("Result: gpio_ddr=%d, gpio_dr=%d\n", kd_pin_get_ddr(pin) ? 1 : 0, kd_pin_get_dr(pin));

    return ret;
}

static int do_k230_gpio(struct cmd_tbl* cmdtp, int flag, int argc, char* const argv[])
{
    int ret = 0;

    if (argc < 3) {
        printf("usage: k230_gpio set/get/in/out pin [value]\n");
        return -1;
    }

    char opt   = argv[1][0];
    int  pin   = simple_strtoul(argv[2], NULL, 0);
    char value = 0;

    if (argc > 3) {
        value = simple_strtoul(argv[3], NULL, 0);
    }

    ret = k230_gpio(opt, pin, &value);

    printf("%c pin %d value %d\n", opt, pin, value);

    return ret;
}

U_BOOT_CMD(k230_gpio, CONFIG_SYS_MAXARGS, 0, do_k230_gpio, "k230_gpio set/get/in/out pin [value]",
           "k230_gpio set/get/in/out pin [value]");
#endif // CONFIG_SPL_BUILD

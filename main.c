/*
 The MIT License (MIT)
 Copyright (c) 2015 Lucas Betschart
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:
 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hidapi.h>
#include "utils.h"
#include "jsmn.h"
#include "commander.h"
#include "flags.h"


#define RANDOM_DATA_FILE  "random_data"
#define HID_REPORT_SIZE   COMMANDER_REPORT_SIZE

extern const char *CMD_STR[];

static const char tests_pwd[] = "0000";
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
static int TEST_LIVE_DEVICE = 1;

static hid_device *HID_HANDLE;
static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};

static int api_hid_init(void)
{
    HID_HANDLE = hid_open(0x03eb, 0x2402, NULL);
    if (!HID_HANDLE) {
        return ERROR;
    }
    return SUCCESS;
}


static void api_hid_read(void)
{
    int res;
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    res = hid_read(HID_HANDLE, HID_REPORT, HID_REPORT_SIZE);
    if (res < 0) {
        printf("ERROR: Unable to read report.\n");
    } else {
        utils_decrypt_report((char *)HID_REPORT);
        //printf("received:  >>%s<<\n", utils_read_decrypted_report());
    }
}


static void api_hid_send_len(const char *cmd, int cmdlen)
{
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    memcpy(HID_REPORT, cmd, cmdlen );
    hid_write(HID_HANDLE, (unsigned char *)HID_REPORT, HID_REPORT_SIZE);
}


static void api_hid_send(const char *cmd)
{
    api_hid_send_len(cmd, strlen(cmd));
}


static void api_hid_send_encrypt(const char *cmd)
{
    int enc_len;
    char *enc = aes_cbc_b64_encrypt((unsigned char *)cmd, strlen(cmd), &enc_len,
                                    PASSWORD_STAND);
    api_hid_send_len(enc, enc_len);
    free(enc);
}

static void api_send_cmd(const char *command, PASSWORD_ID id)
{
    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command, strlen(command));
    }
    if (!TEST_LIVE_DEVICE) {
        utils_send_cmd(command, id);
    } else if (id == PASSWORD_NONE) {
        api_hid_send(command);
        api_hid_read();
    } else {
        api_hid_send_encrypt(command);
        api_hid_read();
    }
}


static void api_format_send_cmd(const char *cmd, const char *val, PASSWORD_ID id)
{
    char command[COMMANDER_REPORT_SIZE] = {0};
    strcpy(command, "{\"");
    strcat(command, cmd);
    strcat(command, "\": ");
    if (val[0] == '{') {
        strcat(command, val);
    } else {
        strcat(command, "\"");
        strcat(command, val);
        strcat(command, "\"");
    }
    strcat(command, "}");
    api_send_cmd(command, id);
}


static const char *api_read_value(int cmd)
{
    int len;
    return jsmn_get_value_string(utils_read_decrypted_report(), CMD_STR[cmd], &len);
}


static int api_result_has(const char *str)
{
    char *report = utils_read_decrypted_report();
    if (report) {
        char *err;
        //printf("report is:   >>%s\n", report);
        //printf("report has:  >>%s\n\n", str);
        err = strstr(report, str);
        if (err) {
            return 1;
        }
    }
    return 0;
}

void random_checks()
{
    printf("########## ent ##########\n");
    system("ent " RANDOM_DATA_FILE);
    printf("\n\n");
    printf("########## dieharder ##########\n");
    system("dieharder -a -f" RANDOM_DATA_FILE);
    printf("\n\n");
    printf("########## rngtest ##########\n");
    if(system("cat " RANDOM_DATA_FILE " | rngtest") != 0)
    {
        // at least one block fails the FIPS tests
        printf("rngtest Error: at least one block fails the FIPS tests\n\n");
        exit(1);
    }
    printf("\n\n\n\n");
    remove(RANDOM_DATA_FILE);
}


int main()
{
    //memory_write_aeskey(tests_pwd, 4, PASSWORD_STAND);  lclc RAUS
    if (api_hid_init() == ERROR) {
        printf("\n\nNot testing HID API. A device is not connected.\n\n");
        return 1;
    } else {
        char number0[32] = {0};

        //api_format_send_cmd("reset", "__ERASE__", PASSWORD_NONE);
        api_format_send_cmd("password", tests_pwd, PASSWORD_NONE);
        if (api_result_has("error")) {
            return 1;
        }


        FILE *f = fopen(RANDOM_DATA_FILE, "w");
        if (f == NULL) {
            printf("tests_entropy: Error opening random_data file!\n");
            return 1;
        }

        //get lots of pseudo random data and write it into a file
        for (int c = 0; c < 8192; c++) {
            api_format_send_cmd("random", "pseudo", PASSWORD_STAND);
            if (api_result_has("error")) {
                return 1;
            }
            memcpy(number0, api_read_value(CMD_random_), sizeof(number0));
            fprintf(f, "%s", number0);
        }
        fclose(f);

        printf("#################### Testing pseudo random ####################\n");
        random_checks();


        f = fopen(RANDOM_DATA_FILE, "w");
        if (f == NULL) {
            printf("tests_entropy: Error opening random_data file!\n");
            return 1;
        }
        //get lots of true random data and write it into a file
        for (int c = 0; c < 8192; c++) {
            api_format_send_cmd("random", "true", PASSWORD_STAND);
            if (api_result_has("error")) {
                return 1;
            }
            memcpy(number0, api_read_value(CMD_random_), sizeof(number0));
            fprintf(f, "%s", number0);
        }
        fclose(f);

        printf("#################### Testing true random ####################\n");
        random_checks();
    }
    return 0;
}

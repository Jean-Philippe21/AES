/**
 * @file main.c
 *
 * @brief main program
 *
 * @author Arnaud ROSAY
 * @date Sep 16, 2021
*/

#define MAIN_C

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "aes.h"
#include "aes_log.h"

/* Global variables */


/* prototypes */
void int_handler(int32_t sig);
uint64_t get_timestamp_nsec(void);
void part1(void);
void part2(void);
void part3(void);
void part4(void);
void measure_exectime(void);

/* functions */
/**
 * @brief Exit properly program in case of CTRL-C
 * @param[in] sig interrupt signal, CTRL-C
 */
void int_handler(int32_t sig)
{
    signal(sig, SIG_IGN);
    printf("Program terminated by Ctrl-C\n");
    exit(EXIT_SUCCESS);
}

/**
 * @brief Provide a timestamp in ns
 * @return timestamp value in ns
 */
uint64_t get_timestamp_nsec(void)
{
    uint64_t timestamp_nsec;
    struct timespec timestamp;
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    timestamp_nsec = (uint64_t)timestamp.tv_sec * (uint64_t)1e9;
    timestamp_nsec += (uint64_t)timestamp.tv_nsec;
    return timestamp_nsec;
}

/**
 * @brief function corresponding to TP-AES Part1
 */
void part1(void)
{
    uint8_t clear_text[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                              0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    aes_key_t cipher_key;
    aes_block_t state;
    /* set data to 0 */
    memset(&cipher_key, 0, sizeof(aes_key_t));
    memset(&state, 0, sizeof(aes_block_t));
    /* prepare AES key */
    memcpy(&cipher_key.byte, key, sizeof(key));
    cipher_key.length = AES128_KEY_SIZE/8;
    aes_key2mat(&cipher_key);
    /* prepare AES state */
    memcpy(&state.byte, clear_text, sizeof(clear_text));
    aes_block2mat(&state);

#ifdef DBG_LOG
    {
        char *msg = "input";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
    {
        char *msg = "k_sch";
        log_print_key(&cipher_key, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_key(&cipher_key, msg, strlen(msg));
    }
    {
        /* display input as a matric */
        char *msg = "input as matrix";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_MAT);
    }
#endif /*  DBG_LOG */
    aes_addroundkey(&state, &cipher_key);
#ifdef DBG_LOG
    {
        char *msg = "start";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_subbytes(&state);
#ifdef DBG_LOG
    {
        char *msg = "s_box";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_shiftrows(&state);
#ifdef DBG_LOG
    {
            char *msg = "s_row";
            log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
            log_write_block(&state, msg, strlen(msg));
        }
#endif /*  DBG_LOG */
    aes_mixcolumns(&state);
#ifdef DBG_LOG
    {
            char *msg = "m_col";
            log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
            log_write_block(&state, msg, strlen(msg));
        }
#endif /*  DBG_LOG */
}

/**
 * @brief function corresponding to TP-AES Part2
 */
void part2(void)
{
    uint8_t clear_text[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    /* Write your code here */
    
    aes_block_t ciphered_block;
    aes_block_t clear_block;
    aes_key_t cipher_key;
    
    /* set data to 0 */
    memset(&cipher_key, 0, sizeof(aes_key_t));
    memset(&clear_block, 0, sizeof(aes_block_t));
    memset(&ciphered_block, 0, sizeof(aes_block_t));
    /* prepare AES state */
    memcpy(&clear_block.byte, clear_text, sizeof(clear_text));
    aes_block2mat(&clear_block);
    /* prepare AES key */
    memcpy(&cipher_key.byte, key, sizeof(key));
    cipher_key.length = AES128_KEY_SIZE/8;
    aes_key2mat(&cipher_key);
 
 
 
    aes_cipher(&ciphered_block,&clear_block,&cipher_key);
    
    //measure_exectime();
    
}

/**
* @brief function corresponding to TP-AES Part3
*/
void part3(void)
{
    uint8_t ciphered_text[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    aes_key_t decipher_key;
    aes_block_t state;
    /* set data to 0 */
    memset(&decipher_key, 0, sizeof(aes_key_t));
    memset(&state, 0, sizeof(aes_block_t));
    /* prepare AES key */
    memcpy(&decipher_key.byte, key, sizeof(key));
    decipher_key.length = AES128_KEY_SIZE/8;
    aes_key2mat(&decipher_key);
    /* prepare AES state */
    memcpy(&state.byte, ciphered_text, sizeof(ciphered_text));
    aes_block2mat(&state);
    /* decipher_key expansion */
    aes_key_t *round_keys[11];
    aes_key_t *(*expanded_keys)[] = &round_keys;
    for (uint32_t i=0;i<11;i++) {
        round_keys[i] = calloc(1, sizeof(aes_key_t));
    }
    memcpy(round_keys[0], &decipher_key, sizeof(aes_key_t));
    aes_keyexpansion(expanded_keys, &decipher_key);

    /* test AddRoundKey */
#ifdef DBG_LOG
    {
        char *msg = "iinput";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
    {
        char *msg = "ik_sch";
        log_print_key(round_keys[10], msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_key(round_keys[10], msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_addroundkey(&state, round_keys[10]);
    /* test InvShiftRows */
#ifdef DBG_LOG
    {
        char *msg = "ik_sch";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_invshiftrows(&state);
#ifdef DBG_LOG
    {
        char *msg = "is_row";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_invsubbytes(&state);
#ifdef DBG_LOG
    {
            char *msg = "is_box";
            log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
            log_write_block(&state, msg, strlen(msg));
        }
#endif /*  DBG_LOG */
#ifdef DBG_LOG
    {
        char *msg = "ik_sch";
        log_print_key(round_keys[9], msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_key(round_keys[9], msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_addroundkey(&state, round_keys[9]);
#ifdef DBG_LOG
    {
        char *msg = "ik_add";
        log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
        log_write_block(&state, msg, strlen(msg));
    }
#endif /*  DBG_LOG */
    aes_invmixcolumns(&state);
#ifdef DBG_LOG
    {
            char *msg = "im_col";
            log_print_block(&state, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
            log_write_block(&state, msg, strlen(msg));
        }
#endif /*  DBG_LOG */
}

/**
* @brief function corresponding to TP-AES Part4
*/
void part4(void)
{
    uint8_t clear_text[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    aes_key_t cipher_key;
    aes_block_t clear_block, ciphered_block, deciphered_block;
    uint64_t timestamp_nsec;
    struct timespec timestamp;

    /* Write your code here */

    /* deactivate DBG_LOG to measure time */
#ifndef DBG_LOG
    measure_exectime();
#endif /* DGB_LOG */
}

/**
* @brief function measuring the average exection time
*/
void measure_exectime(void)
{
    uint8_t clear_text[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    /* Write your code here */
    
    aes_block_t ciphered_block;
    aes_block_t clear_block;
    aes_key_t cipher_key;
    
    //pour stocker le temps d'exécution du code
    double time_spent = 0;
    
    clock_t begin = clock();
    
    for (uint32_t r=0;r<1000;r++) {
    	/* set data to 0 */
	    memset(&cipher_key, 0, sizeof(aes_key_t));
	    memset(&clear_block, 0, sizeof(aes_block_t));
	    memset(&ciphered_block, 0, sizeof(aes_block_t));
	    /* prepare AES state */
	    memcpy(&clear_block.byte, clear_text, sizeof(clear_text));
	    aes_block2mat(&clear_block);
	    /* prepare AES key */
	    memcpy(&cipher_key.byte, key, sizeof(key));
	    cipher_key.length = AES128_KEY_SIZE/8;
	    aes_key2mat(&cipher_key);
	 
	 
	 
	    aes_cipher(&ciphered_block,&clear_block,&cipher_key);
    }
    
    clock_t end = clock();
    
    // calcule le temps écoulé en trouvant la différence (end - begin) et divisant la différence par CLOCKS_PER_SEC pour convertir en secondes
    time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
    
    printf("The elapsed time is %f seconds\n\n", time_spent);
}

/**
 * @brief Main process
 * @return 0 when process is terminated
 */
int main(void)
{
    /* install int handler to catch Ctrl-C */
    signal(SIGINT, int_handler);
    /* init logger */
    log_init("./log.txt");
    /* TP is divided in 4 parts */
    printf("=========================================\n");
    printf(" Part 1\n");
    printf("-----------------------------------------\n");
    part1();
    printf("=========================================\n");
    printf(" Part 2\n");
    printf("-----------------------------------------\n");
    part2();
    printf("=========================================\n");
    printf(" Part 3\n");
    printf("-----------------------------------------\n");
    part3();
    printf("=========================================\n");
    printf(" Part 4\n");
    printf("-----------------------------------------\n");
    part4();
    /* stop logger */
    log_deinit();
    return(0);
}

#undef MAIN_C

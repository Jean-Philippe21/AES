/**
 * @file aes.c
 * @brief AES implementation
 *
 * @author Arnaud ROSAY
 * @date Sep 16, 2021
*/

#define AES_C

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "aes.h"
#include "aes_log.h"


/**
 * @brief cipher one AES block
 * @param[in,out] ciphered_block pointer to the ciphered data
 * @param[in] clear_block pointer to the block of clear data
 * @param[in] key pointer to the cipher/decipher key
 */
void aes_cipher(aes_block_t *ciphered_block, aes_block_t *clear_block,aes_key_t *cipher_key)
{
    /* write your code here */
    /* parameter verification */
    if (clear_block == NULL || ciphered_block==NULL || cipher_key==NULL) {
        fprintf(stderr, "[ERROR] aes_cipher: bad input parameter\n");
        exit(EXIT_FAILURE);
    }
    
            /* cipher_key expansion */ 
	    aes_key_t *round_keys[11];
	    aes_key_t *(*expanded_keys)[]= &round_keys;
	    for (uint32_t i=0;i<11;i++) {
		round_keys[i] = calloc(1, sizeof(aes_key_t));
	    }
	    memcpy(round_keys[0], cipher_key, sizeof(aes_key_t));
	    aes_keyexpansion(expanded_keys,cipher_key);
	    
	    
	    /* prepare AES ciphered_block */
	    memcpy(ciphered_block->byte,clear_block->byte,sizeof(clear_block->byte));
	    aes_block2mat(ciphered_block);
	    
	    
	    #ifdef DBG_LOG
	    {
		char *msg = "input";
		log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
		log_write_block(ciphered_block, msg, strlen(msg));
	    }
	    {
		char *msg = "k_sch";
		log_print_key(cipher_key, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
		log_write_key(cipher_key, msg, strlen(msg));
	    }
	    #endif /*  DBG_LOG */
	    
	    /*Initial Round*/
	    aes_addroundkey(ciphered_block,round_keys[0]);
	    
	    /*9 Rounds*/
	    for (uint32_t i=0;i<9;i++){
	    	    #ifdef DBG_LOG
		    {
			char *msg = "start";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		    aes_subbytes(ciphered_block);
		    #ifdef DBG_LOG
		    {
			char *msg = "s_box";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    	    aes_shiftrows(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "s_row";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    	    aes_mixcolumns(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "m_col";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		    #ifdef DBG_LOG
		    {
			char *msg = "input";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    {
			char *msg = "k_sch";
			log_print_key(cipher_key, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_key(cipher_key, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		    aes_addroundkey(ciphered_block,round_keys[i+1]);
		    
	    }
	    
	    /*Final Round*/
	    aes_subbytes(ciphered_block);
		    #ifdef DBG_LOG
		    {
			char *msg = "s_box";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    aes_shiftrows(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "s_row";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    
    	    aes_addroundkey(ciphered_block,round_keys[10]);
    	     
    	     	    #ifdef DBG_LOG
		    {
			    char *msg = "output";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
    	
}

/**
 * @brief decipher one AES block
 * @param[in,out] clear_block pointer to the block of clear data
 * @param[in] ciphered_block pointer to the ciphered data
 * @param[in] decipher_key pointer to the cipher/decipher decipher_key
 */
void aes_decipher(aes_block_t *clear_block, aes_block_t *ciphered_block,
                  aes_key_t *decipher_key)
{
    /* write your code here */
    /* parameter verification */
    if (clear_block == NULL || ciphered_block==NULL || decipher_key==NULL) {
        fprintf(stderr, "[ERROR] aes_cipher: bad input parameter\n");
        exit(EXIT_FAILURE);
    }
    
            /* cipher_key expansion */ 
	    aes_key_t *round_keys[11];
	    aes_key_t *(*expanded_keys)[]= &round_keys;
	    for (uint32_t i=0;i<11;i++) {
		round_keys[i] = calloc(1, sizeof(aes_key_t));
	    }
	    memcpy(round_keys[10], decipher_key, sizeof(aes_key_t));
	    aes_keyexpansion(expanded_keys,decipher_key);
	    
	    
	    /* prepare AES ciphered_block */
	    memcpy(ciphered_block->byte,clear_block->byte,sizeof(clear_block->byte));
	    aes_block2mat(ciphered_block);
	    
	    #ifdef DBG_LOG
	    {
		char *msg = "iinput";
		log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
		log_write_block(ciphered_block, msg, strlen(msg));
	    }
	    {
		char *msg = "ik_sch";
		log_print_key(decipher_key, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
		log_write_key(decipher_key, msg, strlen(msg));
	    }
	    #endif /*  DBG_LOG */
	    
	    /*Initial Round*/
	    aes_addroundkey(ciphered_block,round_keys[10]);
	    
	    	    #ifdef DBG_LOG
		    {
			char *msg = "istart";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    aes_invshiftrows(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "is_row";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    aes_invsubbytes(ciphered_block);
		    #ifdef DBG_LOG
		    {
			char *msg = "is_box";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
    	   for (uint32_t i=9;i>0;i--){
    	   	   
    	   	    aes_addroundkey(ciphered_block,round_keys[i]);
	    	    #ifdef DBG_LOG
		    {
			char *msg = "istart";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		    aes_invmixcolumns(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "im_col";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		    aes_invshiftrows(ciphered_block);
	    	    #ifdef DBG_LOG
		    {
			    char *msg = "is_row";
			    log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			    log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
	    	    aes_invsubbytes(ciphered_block);
		    #ifdef DBG_LOG
		    {
			char *msg = "is_box";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
		   
	   }
	   
	   aes_addroundkey(ciphered_block,round_keys[0]);
	    	    #ifdef DBG_LOG
		    {
			char *msg = "ioutput";
			log_print_block(ciphered_block, msg, strlen(msg), LOG_MODE_BYTE_SEQ);
			log_write_block(ciphered_block, msg, strlen(msg));
		    }
		    #endif /*  DBG_LOG */
    
}

/**
 * @brief update matrix to reflect the byte sequence of a block
 * @param[in,out] block pointer to the AES block structure
 */
void aes_block2mat(aes_block_t *block)
{
    /* parameter verification */
    if (block == NULL) {
        fprintf(stderr, "[ERROR] aes_block2mat: bad input parameter\n");
        exit(EXIT_FAILURE);
    }

    for (uint32_t r=0;r<4;r++) {
        for (uint32_t c=0;c<AES_NB;c++) {
            block->mat[r][c] = block->byte[r+4*c];
        }
    }
}

/**
 * @brief update byte sequence to reflect the matrix of a block
 * @param[in,out] block pointer to the AES block structure
 */
void aes_mat2block(aes_block_t *block)
{
    /* parameter verification */
    if (block == NULL) {
        fprintf(stderr, "[ERROR] aes_mat2block: bad input parameter\n");
        exit(EXIT_FAILURE);
    }

    for (uint32_t r=0;r<4;r++) {
        for (uint32_t c=0;c<AES_NB;c++) {
            block->byte[r+4*c] = block->mat[r][c];
        }
    }
}

/**
 * @brief update matrix to reflect the byte sequence of a key
 * @param[in,out] key pointer to the AES key structure
 */
void aes_key2mat(aes_key_t *key)
{
    /* parameter verification */
    if (key == NULL) {
        fprintf(stderr, "[ERROR] aes_key2mat: bad input parameter\n");
        exit(EXIT_FAILURE);
    }

    uint32_t nk=0;
    switch (key->length) {
        case AES128_KEY_SIZE/8:
            nk = AES128_NK;
            break;
        case AES192_KEY_SIZE/8:
            nk = AES192_NK;
            break;
        case AES256_KEY_SIZE/8:
            nk = AES256_NK;
            break;
        default:
            fprintf(stderr, "[ERROR] aes_key2mat: bad input parameter\n");
    }
    for (uint32_t r=0;r<4;r++) {
        for (uint32_t c=0;c<nk;c++) {
            key->mat[r][c] = key->byte[r+4*c];
        }
    }
}

/**
 * @brief update byte sequence to reflect the matrix of a key
 * @param[in,out] key pointer to the AES key structure
 */
void aes_mat2key(aes_key_t *key)
{
    /* parameter verification */
    if (key == NULL) {
        fprintf(stderr, "[ERROR] aes_mat2key: bad input parameter\n");
        exit(EXIT_FAILURE);
    }

    uint32_t nk=0;
    switch (key->length) {
        case AES128_KEY_SIZE/8:
            nk = AES128_NK;
            break;
        case AES192_KEY_SIZE/8:
            nk = AES192_NK;
            break;
        case AES256_KEY_SIZE/8:
            nk = AES256_NK;
            break;
        default:
            fprintf(stderr, "[ERROR] aes_key2mat: bad input parameter\n");
    }
    for (uint32_t r=0;r<4;r++) {
        for (uint32_t c=0;c<nk;c++) {
            key->byte[r+4*c] = key->mat[r][c];
        }
    }

}

/**
 * @brief add round key to state matrix
 * @param[in,out] state pointer to state structure
 * @param[in] key pointer to the round key
 */
void aes_addroundkey(aes_block_t *state, aes_key_t *key)
{
    /* write your code here */
     if(state==NULL || key==NULL){

	 fprintf(stderr, "[ERROR] aes_addroundkey: bad input parameter\n");

	 exit(EXIT_FAILURE);

      }else{

	 for( uint32_t i=0; i<AES_BLOCK_SIZE; i++){

		 state->byte[i] =state->byte[i]^key->byte[i];
     	
     	 } 

 	aes_block2mat(state);
      }
}

/**
 * @brief substitute bytes using Sbox
 * @param[in,out] state pointer to the state structure
 */
void aes_subbytes(aes_block_t *state)
{
    /* write your code here */
    
	 uint8_t chiffre_dizaine, chiffre_unite;

	 if(state==NULL){

	 fprintf(stderr, "[ERROR] aes_subbytes: bad input parameter\n");

	 exit(EXIT_FAILURE);

	 }else{

		 for( uint32_t i=0; i<AES_BLOCK_SIZE; i++){

		 //extraction des unites et des dizaines

		 chiffre_dizaine = state->byte[i] & 0xF0;

		 chiffre_dizaine = chiffre_dizaine >> 4;

		 chiffre_unite= state->byte[i] & 0x0F; 

		 state->byte[i] = aes_sbox[chiffre_dizaine][chiffre_unite];

		 }



		 //printf("d:%d u:%d",chiffre_dizaine,chiffre_unite);

		 aes_block2mat(state);

	 }
}

/**
 * @brief inverse substitute bytes using inverse Sbox
 * @param[in,out] state pointer to the state structure
 */
void aes_invsubbytes(aes_block_t *state)
{
    /* write your code here */
    uint8_t chiffre_dizaine, chiffre_unite;

	 if(state==NULL){

	 fprintf(stderr, "[ERROR] aes_subbytes: bad input parameter\n");

	 exit(EXIT_FAILURE);

	 }else{

		 for( uint32_t i=0; i<AES_BLOCK_SIZE; i++){

		 //extraction des unites et des dizaines

		 chiffre_dizaine = state->byte[i] & 0xF0;

		 chiffre_dizaine = chiffre_dizaine >> 4;

		 chiffre_unite= state->byte[i] & 0x0F; 

		 state->byte[i] = aes_inv_sbox[chiffre_dizaine][chiffre_unite];

		 }



		 //printf("d:%d u:%d",chiffre_dizaine,chiffre_unite);

		 aes_block2mat(state);

	 }
}

inline void aes_one_rotation(uint8_t *row){
	
	uint8_t temp;
	
	temp = row[0];
	
	row[0] = row[1];
	
	row[1] = row[2];
	
	row[2] = row[3];
	
	row[3] = temp;
	
}

inline void aes_one_rotation_right(uint8_t *row){
	
	uint8_t temp;
	
	temp = row[3];
	
	row[3] = row[2];
	
	row[2] = row[1];
	
	row[1] = row[0];
	
	row[0] = temp;
	
}

/**
 * @brief shift rows with a circular permutation
 * @param[in,out] state pointer to the state structure
 */
void aes_shiftrows(aes_block_t *state)
{
    /* write your code here */
    if(state==NULL){

	 fprintf(stderr, "[ERROR] aes_subbytes: bad input parameter\n");

	 exit(EXIT_FAILURE);

    }else{

	 //shiftRows ligne 2 de la matrice

	 aes_one_rotation(state->mat[1]);
	 
	 //shiftRows ligne 3 de la matrice

	 aes_one_rotation(state->mat[2]);

	 aes_one_rotation(state->mat[2]);



	 //shiftRows ligne 4 de la matrice

	 aes_one_rotation(state->mat[3]);

	 aes_one_rotation(state->mat[3]);

	 aes_one_rotation(state->mat[3]);
	 
	 //aes_block2mat(state);

	 aes_mat2block(state);
	 }
}

/**
 * @brief inverse shift rows with a circular permutation
 * @param[in,out] state pointer to the state structure
 */
void aes_invshiftrows(aes_block_t *state)
{
    /* write your code here */
    if(state==NULL){

	 fprintf(stderr, "[ERROR] aes_subbytes: bad input parameter\n");

	 exit(EXIT_FAILURE);

    }else{

	 //shiftRows ligne 2 de la matrice

	 aes_one_rotation_right(state->mat[1]);
	 
	 //shiftRows ligne 3 de la matrice

	 aes_one_rotation_right(state->mat[2]);

	 aes_one_rotation_right(state->mat[2]);



	 //shiftRows ligne 4 de la matrice

	 aes_one_rotation_right(state->mat[3]);

	 aes_one_rotation_right(state->mat[3]);

	 aes_one_rotation_right(state->mat[3]);
	 
	 //aes_block2mat(state);

	 aes_mat2block(state);
	 }
}

/**
 * @brief multiply by the value by x ({02})
 * @param[in] in_val value to multiply
 * @return out_val result of the operation
 */
uint8_t aes_xtime(uint8_t in_val)
{
    /* write your code here */
    uint8_t  result;
    
    /*if(in_val==0){

	 fprintf(stderr, "[ERROR] aes_multiply: bad input parameter\n");

	 exit(EXIT_FAILURE);*/

    //}else{
    	result = in_val << 1;
   	if((0x80&in_val)==0x80){
   		
    		result = result^((uint8_t)0x1b);
   	}
    //}
    
    return result;
}


/**
 * @brief mix column with a linear transformation
 * @param[in,out] state pointer to the state structure
 */
void aes_mixcolumns(aes_block_t *state)
{
    /* write your code here */
   
    aes_block_t state_temp;
    
    for( uint32_t i=0; i<4; i++){
    	state_temp.mat[0][i] = 	aes_xtime(state->mat[0][i])^
    				(aes_xtime(state->mat[1][i])^state->mat[1][i])^
    				 state->mat[2][i]^
    				 state->mat[3][i];
    	state_temp.mat[1][i] = 	state->mat[0][i]^
    				aes_xtime(state->mat[1][i])^
    				(aes_xtime(state->mat[2][i])^state->mat[2][i])^
    				 state->mat[3][i];
    	state_temp.mat[2][i] = 	state->mat[0][i]^
    				state->mat[1][i]^
    				aes_xtime(state->mat[2][i])^
    				(aes_xtime(state->mat[3][i])^state->mat[3][i]);
    				
    	state_temp.mat[3][i] = 	(aes_xtime(state->mat[0][i])^state->mat[0][i])^
    				state->mat[1][i]^
    				state->mat[2][i]^
    				aes_xtime(state->mat[3][i]);

    }
    
    for( uint32_t i=0; i<4; i++){
    	 for( uint32_t j=0; j<4; j++){
    	 	state->mat[i][j]=state_temp.mat[i][j];
    	 	//printf("\t%x",state_temp.mat[i][j]);
    	 }
    }
    
    aes_mat2block(state);
}

/**
 * @brief multiply by the val1 by val2
 * @param[in] val1 value to multiply
 * @param[in] val2 value to multiply
 * @return out_val result of the operation
 * @note val2 is expected to be {0e}, {0b}, {0d}, {09} (used in invMixColumns)
 */
uint8_t aes_multiply(uint8_t val1, uint8_t val2)
{
    /* write your code here */
    uint8_t result=0;
    
    if(val2==((uint8_t)0x0e)){
    	result = aes_xtime(aes_xtime(aes_xtime(val1)^val1)^(val1));
    }
    
    if(val2==((uint8_t)0x0b)){
    	result = aes_xtime(aes_xtime(aes_xtime(val1))^(val1))^(val1);
    }
   
    if(val2==((uint8_t)0x0d)){
    	result = aes_xtime(aes_xtime(aes_xtime(val1)^(val1)))^val1;
    }
    
    if(val2==((uint8_t)0x09)){
    	result = aes_xtime(aes_xtime(aes_xtime(val1)))^val1;
    }
    
    return result;
    
}

/**
 * @brief inverse mix column with a linear transformation
 * @param[in,out] state pointer to the state structure
 */
void aes_invmixcolumns(aes_block_t *state)
{
    /* write your code here */
    aes_block_t state_temp;
    
    for( uint32_t i=0; i<4; i++){
    	state_temp.mat[0][i] = 	aes_multiply(state->mat[0][i],(uint8_t)0x0e)^
    				aes_multiply(state->mat[1][i],(uint8_t)0x0b)^
    				aes_multiply(state->mat[2][i],(uint8_t)0x0d)^
    				aes_multiply(state->mat[3][i],(uint8_t)0x09);
    				
    				
    				
    	state_temp.mat[1][i] = 	aes_multiply(state->mat[0][i],(uint8_t)0x09)^
    				aes_multiply(state->mat[1][i],(uint8_t)0x0e)^
    				aes_multiply(state->mat[2][i],(uint8_t)0x0b)^
    				aes_multiply(state->mat[3][i],(uint8_t)0x0d);
    				
    				
    				
    	state_temp.mat[2][i] = 	aes_multiply(state->mat[0][i],(uint8_t)0x0d)^
    				aes_multiply(state->mat[1][i],(uint8_t)0x09)^
    				aes_multiply(state->mat[2][i],(uint8_t)0x0e)^
    				aes_multiply(state->mat[3][i],(uint8_t)0x0b);
    	
    	
    	
    				
    	state_temp.mat[3][i] = 	aes_multiply(state->mat[0][i],(uint8_t)0x0b)^
    				aes_multiply(state->mat[1][i],(uint8_t)0x0d)^
  				aes_multiply(state->mat[2][i],(uint8_t)0x09)^
  				aes_multiply(state->mat[3][i],(uint8_t)0x0e);
  				
        
    }
    
    for( uint32_t i=0; i<4; i++){
    	 for( uint32_t j=0; j<4; j++){
    	 	state->mat[i][j]=state_temp.mat[i][j];
    	 	//printf("\t%x",state_temp.mat[i][j]);
    	 }
    }
    
    aes_mat2block(state);
}

/**
 * @brief byte by byte transformation of a word
 * @param[in,out] word 32-bit value corresponding to concatenation of all bytes of a key colum
 * @note used for key expansion
 */
void aes_subword(uint32_t *word)
{
    uint32_t out_word=0;
    uint32_t row;
    uint32_t col;
    uint8_t byte;

    byte = (*word & 0xff000000) >> 24;
    row = (byte & 0xf0) >> 4;
    col = byte & 0x0f;
    out_word = aes_sbox[row][col] << 24;
    byte = (*word & 0x00ff0000) >> 16;
    row = (byte & 0xf0) >> 4;
    col = byte & 0x0f;
    out_word |= aes_sbox[row][col] << 16;
    byte = (*word & 0x0000ff00) >> 8;
    row = (byte & 0xf0) >> 4;
    col = byte & 0x0f;
    out_word |= aes_sbox[row][col] << 8;
    byte = *word & 0x000000ff;
    row = (byte & 0xf0) >> 4;
    col = byte & 0x0f;
    out_word |= aes_sbox[row][col];
    *word = out_word;
}

/**
 * @brief rotation of 1 byte in a word (circular permutation)
 * @param[in,out] word 32-bit value corresponding to concatenation of all bytes of a key colum
 * @note used for key expansion
*/
void aes_rotword(uint32_t *word)
{
    uint32_t tmp=0;
    tmp = *word << 8;
    tmp |= (*word & 0xff000000) >>24;
    *word = tmp;
}

/**
 * @brief calculate round keys from initial key
 * @param[in,out] expanded_key pointer to an array of keys
 * @param[in] key pointer to the initial key
 */
void aes_keyexpansion(aes_key_t *(*expanded_keys)[], aes_key_t* key)
{
    /* parameter verification */
    if ((expanded_keys == NULL) || (key == NULL)) {
        fprintf(stderr, "[ERROR] aes_keyexpansion: bad input parameter\n");
        exit(EXIT_FAILURE);
    }

    uint32_t i=0;
    uint32_t nk=0, nr=0;
    uint8_t w[4][AES256_NR*AES256_NK];
    memset(w, 0, 4*AES256_NK*sizeof(uint8_t));
    switch (key->length) {
        case AES128_KEY_SIZE/8:
            nk = AES128_NK;
            nr = AES128_NR;
            break;
        case AES192_KEY_SIZE/8:
            nk = AES192_NK;
            nr = AES192_NR;
            break;
        case AES256_KEY_SIZE/8:
            nk = AES256_NK;
            nr = AES256_NR;
            break;
        default:
            fprintf(stderr, "[ERROR] aes_keyexpansion: bad input parameter\n");
    }
    while (i < nk) {
        for (uint32_t r=0;r<4;r++) {
            w[r][i] = key->mat[r][i];
        }
        i++;
    }
    uint32_t tmp;
    i = nk;
    while (i< AES_NB*(nr+1)) {
        tmp = w[0][i-1] << 24;
        tmp |= w[1][i-1] << 16;
        tmp |= w[2][i-1] <<8;
        tmp |= w[3][i-1];
        if ((i%nk) == 0) {
            aes_rotword(&tmp),
            aes_subword(&tmp);
            tmp ^= aes_rcon[i/nk-1];
        } else {
            if ((nk<6) && (i%nk == 4)) {
                aes_subword(&tmp);
            }
        }
        w[0][i] = w[0][i-nk] ^ ((tmp & 0xff000000) >> 24);
        w[1][i] = w[1][i-nk] ^ ((tmp & 0x00ff0000) >> 16);
        w[2][i] = w[2][i-nk] ^ ((tmp & 0x0000ff00) >> 8);
        w[3][i] = w[3][i-nk] ^ (tmp & 0x000000ff);
        tmp = w[0][i] << 24;
        tmp |= w[1][i] << 16;
        tmp |= w[2][i] <<8;
        tmp |= w[3][i];
        for (uint32_t r=0;r<4;r++) {
            aes_key_t *round_key;
            round_key = (*expanded_keys)[i/4];
            round_key->mat[r][i%4] = w[r][i];
        }
        i++;
    }
    for (i=0;i<(nr+1);i++) {
        aes_key_t *round_key;
        round_key = (*expanded_keys)[i];
        round_key->length = key->length;
        aes_mat2key(round_key);
    }
}

#undef AES_C

/*
 * txxt - small XXTEA encryption utility
 * Copyright (C) 2021 Adam Prycki
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#ifndef XXTEA_MIN_ROUNDS
#define XXTEA_MIN_ROUNDS 8
#endif
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
void
btea(	uint32_t *v,
		int n,
		uint32_t const key[4]){
	
	uint32_t y, z, sum;
	unsigned p, rounds, e;
	if(n>1){	/* Coding Part */
		rounds=XXTEA_MIN_ROUNDS+52/n;
		sum=0;
		z=v[n-1];
		do{
			sum+=DELTA;
			e=(sum>>2)&3;
			for(p=0;p<n-1;p++){
				y=v[p+1]; 
				z=v[p]+=MX;}
			y=v[0];
			z=v[n-1]+=MX;
		}while(--rounds);
	}else if(n<-1){	/* Decoding Part */
		n=-n;
		rounds=XXTEA_MIN_ROUNDS+52/n;
		sum=rounds*DELTA;
		y=v[0];
		do{
			e=(sum>>2)&3;
			for(p=n-1;p>0;p--){
				z=v[p-1];
				y=v[p] -= MX;}
			z=v[n-1];
			y=v[0] -= MX;
			sum-=DELTA;
		}while(--rounds);}}

int
dumpHex(uint64_t size, uint8_t* ptr){
	uint64_t ogSize=size;
	unsigned int lc=0;
	if(!size)return(1);
	if(!ptr)return(1);
	while(size--){
		if(lc==0)fprintf(stderr,"%08lx:\t",(ogSize-size-1)*sizeof(uint8_t));
		fprintf(stderr,"%02x ",*(ptr++)&0xff);
		lc++;
		if(lc%2==0)fprintf(stderr,"	");
		if(lc==16)fprintf(stderr,"\n");
		if(lc>=16)lc=0;}
	fprintf(stderr,"\n");
	return(0);}

void
printHelp(){
	fprintf(stderr," txxt - tiny XXTEA encryption utility.\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"\t XXTEA ISN'T VERY SECURE.\n");
	fprintf(stderr,"\t YOU SHOULDN'T USE IT FOR ANYTHING SERIOUS.\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"\t Without filepaths provided via -i and -o flags, program will \n");
	fprintf(stderr,"\t process data from STDIN and STDOUT.\n");
	fprintf(stderr,"\t You shouldn't use it interactively, but you can.\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"  Avalible flags:\n");
	fprintf(stderr,"\t-h Debug mode\n");
	fprintf(stderr,"\t-k keyfile\n");
	fprintf(stderr,"\t\texample: -k/path/to/keyfile\n");
	fprintf(stderr,"\t-i inputfile\n");
	fprintf(stderr,"\t\texample: -i/path/to/inputfile\n");
	fprintf(stderr,"\t-o outputfile\n");
	fprintf(stderr,"\t\texample: -o/path/to/outputfile\n");
	fprintf(stderr,"\t-d decrypt mode\n");
	fprintf(stderr,"\t-D Debug mode\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"  Usage example:\n");
	fprintf(stderr,"\tencrypt:\n\t\ttxxt -kKEY < plaintext > encrypted\n");
	fprintf(stderr,"\tdecrypt:\n\t\ttxxt -kKEY -D < encrypted > plaintext\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"\tencrypt and provide key from shell (bash only):\n\t\ttxxt -k<(printf \"mykey\") <plaintext >encrypted\n");
	fprintf(stderr,"\tencrypt in Debug mode:\n\t\ttxxt -D -kKEY < plaintext > encrypted\n");
	fprintf(stderr,"\tencrypt from file:\n\t\ttxxt -kKEY -i./file/path > encrypted\n");
	fprintf(stderr,"\tdecrypt to file:\n\t\ttxxt -kKEY -D < encrypted -o./file/path\n");
	fprintf(stderr,"\tdecrypt from file to file:\n\t\ttxxt -kKEY -D -i./inputFile -o./outputFile\n");}

int
main(int argc, char* argv[]){
	int iblck,oblck,cblck,f,DEBUG=0,keyset=0,dec=0,ifile=-2,ofile=-2;
	struct stat statst;
	uint64_t bsize=256,mode=1;
	uint32_t key[4] = {0,0,0,0};
	ssize_t fiorc; /* file input output return code */
	uint8_t* buffer = malloc(sizeof(uint8_t)*bsize);
	
	for(;argc>1&&argv[1][0]=='-';argc--,argv++){
		switch(argv[1][1]){
		case 0:
			break;
		case 'D':
			DEBUG=true;
			continue;
		case 'd':
			mode=-1;
			continue;
		case 'h':
			printHelp();
			exit(EXIT_SUCCESS);
		case 'i':
			if(ifile>=0){
				fprintf(stderr, "input file already specified\n");
				continue;}
			ifile=open(&argv[1][2],O_RDONLY);
			if(ifile==-1){
				perror("error, opening input file");
				exit(EXIT_FAILURE);}
			continue;
		case 'o':
			if(ofile>=0){
				fprintf(stderr, "output file already specified\n");
				continue;}
			ofile=open(&argv[1][2], O_WRONLY | O_CREAT, 0600);
			if(ofile==-1){
				perror("error, opening output file");
				exit(EXIT_FAILURE);}
			continue;
		case 'k':
			f=open(&argv[1][2],O_RDONLY);
			if(f==-1){
				perror("error, opening keyfile");
				exit(EXIT_FAILURE);}
			fiorc = read(f,&key,4*sizeof(uint32_t)); /* 128 bit key / 8 bits per byte = 16 bytes */
			if(fiorc<16)fprintf(stderr,
				"WARNING, key size is not 128 bit long. provided key is %ld bit long\n(paddin end of the key with zeros)\n",
				fiorc*8); /* bytest to bits */
			keyset=true;
			continue;}
		break;}
	if(!keyset)
		fprintf(stderr,"keyfile wasn't provided, exiting...\n"),
		exit(EXIT_FAILURE);
	if(ifile==-2)
		ifile=STDIN_FILENO;
	if(ofile==-2)
		ofile=STDOUT_FILENO;
	
	//if(!ifile||!ofile)
	//	exit(EXIT_FAILURE);
	if(fstat(ifile,&statst)==0)
		oblck=statst.st_blksize;
	else
		oblck=0;
	
	if(fstat(ofile,&statst)==0)
		iblck=statst.st_blksize;
	else
		iblck=0;
	
	if(iblck>oblck)
		cblck=oblck;
	else if(iblck<=oblck)
		cblck=iblck;
	else
		cblck=512;
	
	if(iblck==0||oblck==0)
		cblck=512;
	if(DEBUG)
		fprintf(stderr,"ib %d, ob %d picked %d\n",iblck,oblck,cblck);
	buffer=realloc(buffer,cblck);
	if(!buffer)
		fprintf(stderr,"realloc failed\n"),exit(EXIT_FAILURE);
	if(DEBUG)
		fprintf(stderr,"%d %d\n",ifile,ofile);
	fiorc=0;
	while((fiorc=read(ifile,buffer,cblck))){
		if(fiorc<sizeof(uint32_t)*2){
			fprintf(stderr,"Input data (%ld bits) is shorter than 64bits (8 char). Please insert longer message\n",
			fiorc*8);
			continue;}
		if(DEBUG)
			fprintf(stderr,"read %ld. hexdump:\n",fiorc),
			dumpHex(fiorc,buffer);
		
		btea((uint32_t*)buffer,fiorc*mode/sizeof(uint32_t),key);
		if(DEBUG){
			if(mode==1)
				fprintf(stderr,"encrypted data hexdump (size %ld 32bit ints):\n", fiorc*mode/sizeof(uint32_t));
			if(mode==-1)
				fprintf(stderr,"decrypted data hexdump (size %ld 32bit ints):\n", fiorc*mode/sizeof(uint32_t));
			dumpHex(fiorc,buffer);}
		
		if(write(ofile,buffer,fiorc)==-1)
			perror("failed to write to file"),exit(EXIT_FAILURE);
		
		if(DEBUG){
			btea((uint32_t*)buffer,(-mode)*fiorc/sizeof(uint32_t),key);
			fprintf(stderr,"\nreversing previous operation to check corectness. hexdump:\n");
			dumpHex(fiorc,buffer);}}
	free(buffer);
	close(ifile);
	close(ofile);
	return(0);}

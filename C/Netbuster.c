#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>

//+++++++++++++++++++++++++++++++++++++++++++++++++
//Funçao que Pega Dominio e Transforma em IP
int DNSDissolver (char *Dominio){

    struct hostent *alvo = gethostbyname(Dominio);
    printf("Host:%s|IP:%10s\n",Dominio,inet_ntoa(*((struct in_addr *)alvo-> h_addr)));

    return 0;
}
//+++++++++++++++++++++++++++++++++++++++++++++++++++++

int main(int argc, char **argv){
    if(argc < 2){
        printf("Usage: NetBuster www.site.com\n");
        exit(1);
    } else {
        printf("Resolvendo DNS...\n");
        DNSDissolver(argv[1]);
    }
}
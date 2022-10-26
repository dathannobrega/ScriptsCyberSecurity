#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
//NAO FEITO
//BASE para FAzer PORT SCANNER EM C
int main(int argc, char **argv) {

    struct sockaddr_in alvo;

    int meusocket;
    int conecta;
    meusocket = socket(AF_INET, SOCK_STREAM,0);

    if (meusocket < 0) {
		perror("Could not create socket");
		return 1;
	}
    int ret;
    for (int i = 0; ; i++)
    {

        alvo.sin_addr.s_addr = inet_addr(argv[1]);
        alvo.sin_family = AF_INET;
        alvo.sin_port = htons(21);
        ret = bind  (meusocket,(struct sockaddr *)&alvo,sizeof(alvo));
        printf("Realizando ataque DoS tam: %d\n",i);
        if(ret == -1 )
        {
            printf("Control Socket Connecting Failed\n");
            return -1;
        }

    }
}
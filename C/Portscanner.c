#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

//BASE para FAzer PORT SCANNER EM C
int main(int argc, char **argv) {

    struct sockaddr_in alvo;

    int meusocket;
    int conecta;
    
    for (int i = 0; i < 65535; i++)
    {
        meusocket = socket(AF_INET, SOCK_STREAM,0);
        alvo.sin_family = AF_INET;
        alvo.sin_port = htons(i);
        alvo.sin_addr.s_addr = inet_addr(argv[1]);

        conecta = connect(meusocket,(struct sockaddr *)&alvo,sizeof alvo);
        
        if (conecta == 0)
        { 
            printf("Porta %d Aberta \n",i);
            close(meusocket);
            close(conecta);
        }
    }
    
}
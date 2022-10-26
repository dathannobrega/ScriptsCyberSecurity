#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

//BASE para FAzer PORT SCANNER EM C
int main(void) {
    struct sockaddr_in alvo;

    int meusocket;
    int conecta;

    meusocket = socket(AF_INET, SOCK_STREAM,0);
    alvo.sin_family = AF_INET;
    alvo.sin_port = htons(81);
    alvo.sin_addr.s_addr = inet_addr("192.168.0.1");

    conecta = connect(meusocket,(struct sockaddr *)&alvo,sizeof alvo);
    
    if (conecta == 0)
    {
        printf("Porta Aberta \n");
        close(meusocket);
        close(conecta);
    } else {
        printf("Porta Fechada \n");
    }
    
}
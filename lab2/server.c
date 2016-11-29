#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h> 
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define CACERT "568ca.pem"
#define SERVERCERT "bob.pem"
#define PASSWORD "password"



//Test
//#define CACERT "certificate_test.pem"
//#define SERVERCERT "cert_client_test.pem"


void error_handler_send_receive(int handShakeSSL, SSL *ssl, int len);
void automarker_error_logger(int handShakeSSL, SSL *ssl);
void server_shut_down(int sock, int s, SSL *ssl, SSL_CTX *ctxSSL, X509 *clientCert);
int passwordCallback(char *buf, int size, int rwflag, void *password);
int main(int argc, char **argv)
{
  int port = PORT;
  /****************************************/ 
  /******Parse Command Line Arguments******/
  /****************************************/
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
        fprintf(stderr,"invalid port number");
        exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  } 

  /****************************************/
  /*******Initialize SSL Connections*******/
  /****************************************/
  SSL_library_init();
  OpenSSL_add_ssl_algorithms ();
  SSL_load_error_strings ();
  //Test
  //SSL_METHOD *methSSL =  (SSL_METHOD *)SSLv2_server_method();
  SSL_METHOD *methSSL =  (SSL_METHOD *)SSLv23_server_method();
  // A TLS/SSL connection established with this method will understand the SSLv2, SSLv3, and TLSv1 protocol.
  SSL_CTX *ctxSSL = SSL_CTX_new(methSSL);
  if (ctxSSL == NULL){
    fprintf(stderr, "SERVER: Fatal - Failure reuqesting new context.\nServer Exit...\n");
    exit(0);
  }
  SSL_CTX_set_verify (ctxSSL, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  // The server sends a client certificate request to the client. 
  // If the verification process fails, the TLS/SSL handshake is immediately terminated with an alert message containing the reason for the verification failure. 
  // If the client did not return a certificate, the TLS/SSL handshake is immediately terminated with a "handshake failure" alert.
  SSL_CTX_load_verify_locations (ctxSSL, CACERT, NULL);
  // Load CA certifcation 
  SSL_CTX_set_cipher_list(ctxSSL, "SSLv2:SSLv3:TLSv1");
  //Test
  //SSL_CTX_set_cipher_list(ctxSSL, "  ALL:!SHA1");

  // Support all cipher suites available for SSLv2, SSLv3 and TLSv1
  SSL_CTX_set_default_passwd_cb(ctxSSL, passwordCallback);

  //SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);

  /****************************************/
  /******Load Certifications and Keys******/
  /****************************************/
  if (SSL_CTX_use_certificate_chain_file (ctxSSL, SERVERCERT) == 0){
    fprintf(stderr, "SERVER: Fatal - Failure loading sever certifcation.\nServer Exit...\n");
    server_shut_down(-1, -1, NULL, ctxSSL, NULL);
  }
  if (SSL_CTX_use_PrivateKey_file (ctxSSL, SERVERCERT, SSL_FILETYPE_PEM) == 0){
    fprintf(stderr, "SERVER: Fatal - Failure loading private key file.\nServer Exit...\n");
    server_shut_down(-1, -1, NULL, ctxSSL, NULL);
  }
  if (!SSL_CTX_check_private_key (ctxSSL)){
    fprintf(stderr, "SERVER: Fatal - Private key does not match the certificate public key.\nServer Exit...\n");
    server_shut_down(-1, -1, NULL, ctxSSL, NULL);
  }

  /* SSL CTX Intialization Complete */

  /****************************************/
  /******Initialize Socket Connetions******/
  /****************************************/
  int sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0){
    fprintf(stderr, "SERVER: Fatal - Failure opening socket connetion.\nServer Exit...\n");
    server_shut_down(sock, -1, NULL, ctxSSL, NULL);
  }
  // Socket created
  struct sockaddr_in sin;
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  // Socket address and port set
  int optVal=1;
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &optVal,sizeof(optVal));
  // Socket option set
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0){
    fprintf(stderr, "SERVER: Fatal - Failure binding socket connetion.\nServer Exit...\n");    
    server_shut_down(sock, -1, NULL, ctxSSL, NULL);
  }
  // Socket binded to port
  if(listen(sock,5) < 0){
    fprintf(stderr, "SERVER: Fatal - Failure setting maximum socket connetion.\nServer Exit...\n"); 
    server_shut_down(sock, -1, NULL, ctxSSL, NULL);
  } 
  // Maximum socket connection set

  /* Socket Intialization Complete */

  /****************************************/
  /***Accepting Connections From Clients***/
  /****************************************/
  pid_t pid;
  while(1){
    int s = accept (sock, NULL, 0);
    if (s < 0){
      fprintf(stderr, "SERVER: Fatal - Failure accepting socket connetion.\nServer Exit...\n"); 
      server_shut_down(sock, s, NULL, ctxSSL, NULL);
    }
    /* Socket Connection Established */
    // Fork a child to handle the connection
    if((pid=fork())){
      //Parent Process
      close(s);
    }
    else {
      //Child Process
      SSL *ssl = SSL_new (ctxSSL);
      if (ssl == NULL){
        fprintf(stderr, "SERVER: Fatal - Failure creating SSL structure connetion.\nServer Exit...\n"); 
        server_shut_down(sock, s, NULL, ctxSSL, NULL);
      }
      BIO * bio = BIO_new_socket(s, BIO_NOCLOSE);
      if (bio == NULL){
        fprintf(stderr, "SERVER: Fatal - Failure creating BIO for new socket connection.\nServer Exit...\n"); 
        server_shut_down(sock, s, ssl, ctxSSL, NULL);
      }
      SSL_set_bio(ssl, bio, bio);
      // BIO bineded to SSL

      /****************************************/
      /*******Esatblishing SSL Connection******/
      /****************************************/
      int handShakeSSL = SSL_accept (ssl);
      if (handShakeSSL <= 0){
        // Automarker
        fprintf(stdout, FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        server_shut_down(sock, s, ssl, ctxSSL, NULL);
      }

      /* SSL Connection Established */

      /****************************************/
      /******Verifying SSL Certification*******/
      /****************************************/

      X509 *clientCert = SSL_get_peer_certificate (ssl);
      if (clientCert != NULL && SSL_get_verify_result(ssl) ==  X509_V_OK){
        /* Certification Verified */
       
        /****************************************/
        /***Obtaining Certification Information**/
        /****************************************/
        char commonName[256], email[256];
        X509_NAME * subjectName = X509_get_subject_name(clientCert); 
        X509_NAME_get_text_by_NID(subjectName, NID_commonName, commonName, 256);
        X509_NAME_get_text_by_NID(subjectName, NID_pkcs9_emailAddress, email, 256);
        fprintf(stdout, FMT_CLIENT_INFO, commonName, email);

        /****************************************/
        /*********Receiving Information**********/
        /****************************************/
        char buf[256];
        int lenRead = SSL_read(ssl, &buf, 255);
        if (lenRead <= 0){
          error_handler_send_receive(handShakeSSL, ssl, lenRead);
          server_shut_down(sock, s, ssl, ctxSSL, clientCert);
        }else{
          buf[lenRead]= '\0';
          // Information successfully received 

          //Test
          //exit(0);

          /****************************************/
          /**********Sending Information***********/
          /****************************************/
          char *answer = "42";
          int lenWrite = SSL_write(ssl, answer, strlen(answer));
          if (lenWrite <= 0){
            error_handler_send_receive(handShakeSSL, ssl, lenWrite);
            server_shut_down(sock, s, ssl, ctxSSL, clientCert);
          }else{
            // Information successfully sent
            // Show result to automarker
            fprintf(stdout, FMT_OUTPUT, buf, answer);
            server_shut_down(sock, s, ssl, ctxSSL, clientCert);
          }
        }
      }else{
        /* Certification NOT Verified */
        automarker_error_logger(handShakeSSL, ssl);
        server_shut_down(sock, s, ssl, ctxSSL, clientCert);
      }
    }
  }  
  return 0;
}

void error_handler_send_receive(int handShakeSSL, SSL *ssl, int len){
  if (len < 0){
    automarker_error_logger(handShakeSSL, ssl);
  }else if (len == 0 && SSL_get_error(ssl, handShakeSSL) != SSL_ERROR_ZERO_RETURN && SSL_get_error(ssl, handShakeSSL) != SSL_ERROR_NONE){
    automarker_error_logger(handShakeSSL, ssl);
  }
}

void automarker_error_logger(int handShakeSSL, SSL *ssl){
  if (SSL_get_error(ssl, handShakeSSL) == SSL_ERROR_SYSCALL){
    // SSL client shutdown incorrectly - - show to automarker
    fprintf(stdout, FMT_INCOMPLETE_CLOSE);
  }else if (SSL_get_error(ssl, handShakeSSL) != SSL_ERROR_NONE){
    // SSL accept error - show to automarker
    fprintf(stdout, FMT_ACCEPT_ERR);
    ERR_print_errors_fp(stdout);
  }   
}

void server_shut_down(int sock, int s, SSL *ssl, SSL_CTX *ctxSSL, X509 *clientCert){
  if(ssl != NULL){
    int shutdownSSL = SSL_shutdown(ssl);
    if(shutdownSSL == 0){
      // The shutdown is not yet finished. Call SSL_shutdown() for a second time after a bidirectional shutdown. 
      if (s != -1){
        shutdown(s, SHUT_WR);
        shutdownSSL = SSL_shutdown(ssl);
      }
    }  
    if (SSL_shutdown(ssl) != 1){
      fprintf(stdout, FMT_INCOMPLETE_CLOSE);
    }
    SSL_free(ssl);
  }

  if (clientCert != NULL){
    X509_free (clientCert);
  }

  if (sock != -1){
    close(sock);
  }

  if (s != -1){
    close(s);
  }

  if (ctxSSL != NULL){
    SSL_CTX_free(ctxSSL);
  }

  exit (0);
}

int passwordCallback(char *buf, int size, int rwflag, void *password)
{
  strncpy(buf, PASSWORD, size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}
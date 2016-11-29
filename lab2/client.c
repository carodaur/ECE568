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

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define CACERT "568ca.pem"
#define CLIENTCERT "alice.pem"
#define PASSWORD "password"

//Test
//#define CACERT "certificate_test.pem"
//#define CLIENTCERT "cert_client_test.pem"

#define SERVERCOMMONNAME  "Bob's Server"
#define SERVEREMAIL "ece568bob@ecf.utoronto.ca" 

//Test
//#define SERVERCOMMONNAME  "Bob's Server wrong"
//#define SERVEREMAIL "ece568bob@ecf.utoronto.ca wrong"

void client_shut_down(int sock, SSL *ssl, SSL_CTX *ctxSSL, X509 *serverCert);
void error_handler_send_receive(int handShakeSSL, SSL *ssl, int len);
void automarker_error_logger(int handShakeSSL, SSL *ssl);
int passwordCallback(char *buf, int size, int rwflag, void *password);


int main(int argc, char **argv)
{
  int port=PORT;
  char *host=HOST;
  /****************************************/ 
  /******Parse Command Line Arguments******/
  /****************************************/
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
      	fprintf(stderr,"invalid port number");
      	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /****************************************/
  /*******Initialize SSL Connections*******/
  /****************************************/
  SSL_library_init();
  OpenSSL_add_ssl_algorithms ();
  SSL_load_error_strings ();
  SSL_METHOD *methSSL =  (SSL_METHOD *)SSLv23_client_method();
  // A TLS/SSL connection established with this method will understand the SSLv2, SSLv3, and TLSv1 protocol.
  SSL_CTX *ctxSSL = SSL_CTX_new(methSSL);
  if (ctxSSL == NULL){
    fprintf(stderr, "CLIENT: Fatal - Failure reuqesting new context.\nServer Exit...\n");
    exit(0);
  }
  SSL_CTX_set_options(ctxSSL, SSL_OP_NO_SSLv2);
  // Diable SSLv2
  SSL_CTX_set_verify (ctxSSL, SSL_VERIFY_PEER, NULL);
  // The server certificate is verified. If the verification process fails, the TLS/SSL handshake is immediately terminated with an alert message containing the reason for the verification failure. 
  // If no server certificate is sent, because an anonymous cipher is used, SSL_VERIFY_PEER is ignored.
  SSL_CTX_load_verify_locations (ctxSSL, CACERT, NULL);
  // Load CA certifcation 
  SSL_CTX_set_cipher_list(ctxSSL, "SHA1");
  // Support all cipher suites available for SSLv2, SSLv3 and TLSv1
  //SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);

  /****************************************/
  /******Load Certifications and Keys******/
  /****************************************/
  if (SSL_CTX_use_certificate_chain_file (ctxSSL, CLIENTCERT) == 0){
    fprintf(stderr, "CLIENT: Fatal - Failure loading client certifcation.\nServer Exit...\n");
    client_shut_down(-1, NULL, ctxSSL, NULL);
    exit(0);
  }
  if (SSL_CTX_use_PrivateKey_file (ctxSSL, CLIENTCERT, SSL_FILETYPE_PEM) == 0){
    fprintf(stderr, "CLIENT: Fatal - Failure loading private key file.\nServer Exit...\n");
    client_shut_down(-1, NULL, ctxSSL, NULL);
    exit(0);
  }
  if (!SSL_CTX_check_private_key (ctxSSL)){
    fprintf(stderr, "CLIENT: Fatal - Private key does not match the certificate public key.\nServer Exit...\n");
    client_shut_down(-1, NULL, ctxSSL, NULL);
    exit(0);
  }
  SSL_CTX_set_default_passwd_cb(ctxSSL, passwordCallback);

  /* SSL CTX Intialization Complete */

  /****************************************/
  /******Initialize Socket Connetions******/
  /****************************************/
  struct hostent *host_entry = gethostbyname(host);
  if (!host_entry){
    fprintf(stderr,"CLIENT: Fatal - Couldn't resolve host.\nServer Exit...\n");
    client_shut_down(-1, NULL, ctxSSL, NULL);
    exit(0);
  }
  // Host IP address obtained 
  struct sockaddr_in addr;
  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0){
    fprintf(stderr, "CLIENT: Fatal - Failure opening socket connetion.\nServer Exit...\n");
    client_shut_down(sock, NULL, ctxSSL, NULL);
    exit(0);
  }
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0){
    fprintf(stderr, "CLIENT: Fatal - Failure establishing socket connetion.\nServer Exit...\n");
    client_shut_down(sock, NULL, ctxSSL, NULL);
    exit(0);
  }

  /* Socket Intialization Complete */

  /****************************************/
  /*******Establishing SSL to Server*******/
  /****************************************/
  SSL *ssl = SSL_new (ctxSSL);
  if (ssl == NULL){
    fprintf(stderr, "CLIENT: Fatal - Failure creating SSL structure connetion.\nServer Exit...\n"); 
    client_shut_down(sock, ssl, ctxSSL, NULL);
    exit (0);
  }
  BIO * bio = BIO_new_socket(sock, BIO_NOCLOSE);
  if (bio == NULL){
    fprintf(stderr, "CLIENT: Fatal - Failure creating BIO for new socket connection.\nServer Exit...\n"); 
    client_shut_down(sock, ssl, ctxSSL, NULL);
    exit (0);
  }
  SSL_set_bio(ssl, bio, bio);
  // BIO bineded to SSL

  /****************************************/
  /*******Esatblishing SSL Connection******/
  /****************************************/
  int handShakeSSL = SSL_connect (ssl);
  if (handShakeSSL <= 0){
    // Automarker
    fprintf(stdout, FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
    client_shut_down(sock, ssl, ctxSSL, NULL);
    exit (0);
  }

  /* SSL Connection Established */

  /****************************************/
  /******Verifying SSL Certification*******/
  /****************************************/

  X509 *serverCert = SSL_get_peer_certificate (ssl);
  if (serverCert != NULL && SSL_get_verify_result(ssl) ==  X509_V_OK){
    /* Certification Verified */
       
    /****************************************/
    /***Obtaining Certification Information**/
    /****************************************/
    char commonName[256], email[256], certIssuer[256];
    X509_NAME * subjectName = X509_get_subject_name(serverCert); 
    X509_NAME_get_text_by_NID(subjectName, NID_commonName, commonName, 256);
    X509_NAME_get_text_by_NID(subjectName, NID_pkcs9_emailAddress, email, 256);
    X509_NAME *issuerName = X509_get_issuer_name(serverCert);
    X509_NAME_get_text_by_NID(issuerName, NID_commonName, certIssuer, 256);
    

    if(strcmp(SERVERCOMMONNAME, commonName) != 0){
      //Show reuslt to automarker 
      fprintf(stdout, FMT_CN_MISMATCH);
      client_shut_down(sock, ssl, ctxSSL, serverCert);
      return 0;
    }
    if(strcmp(SERVEREMAIL, email)!=0){
      //Show reuslt to automarker 
      fprintf(stdout, FMT_EMAIL_MISMATCH);
      client_shut_down(sock, ssl, ctxSSL, serverCert);
      return 0;
    }

    // Show result to automarker
    fprintf(stdout, FMT_SERVER_INFO, commonName, email, certIssuer);

    /****************************************/
    /**********Sending Information***********/
    /****************************************/
    char *secret = "What's the question?";
    int lenWrite = SSL_write(ssl, secret, strlen(secret));
    if (lenWrite <= 0){
      error_handler_send_receive(handShakeSSL, ssl, lenWrite);
      client_shut_down(sock, ssl, ctxSSL, serverCert);
      exit (0);
    }else{
      // Information successfully sent
      /****************************************/
      /*********Receiving Information**********/
      /****************************************/

      //Test
      //return 0;

      char buf[256];
      int lenRead = SSL_read(ssl, &buf, 255);
      if (lenRead <= 0){
        error_handler_send_receive(handShakeSSL, ssl, lenRead);
        client_shut_down(sock, ssl, ctxSSL, serverCert);
        exit (0);
      }else{
        // Information successfully received
        buf[lenRead]='\0';
        // Show reuslt to automarker
        fprintf(stdout, FMT_OUTPUT, secret, buf);
        client_shut_down(sock, ssl, ctxSSL, serverCert);
        return 0;
      }
    }
  }else{
    /* Certification NOT Verified */
    fprintf(stdout, FMT_NO_VERIFY);
    //automarker_error_logger(handShakeSSL, ssl);
    client_shut_down(sock, ssl, ctxSSL, serverCert);
    exit (0);
  }
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
    fprintf(stdout, FMT_INCORRECT_CLOSE);
  }else if (SSL_get_error(ssl, handShakeSSL) != SSL_ERROR_NONE){
    // SSL accept error - show to automarker
    fprintf(stdout, FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
  }   
}
void client_shut_down(int sock, SSL *ssl, SSL_CTX *ctxSSL, X509 *serverCert){
  if(ssl != NULL){
    int shutdownSSL = SSL_shutdown(ssl);
    if(shutdownSSL == 0){
      // The shutdown is not yet finished. Call SSL_shutdown() for a second time after a bidirectional shutdown. 
      if (sock != -1){
        shutdown(sock, SHUT_WR);
        shutdownSSL = SSL_shutdown(ssl);
      }
    }  
    if (SSL_shutdown(ssl) != 1){
      fprintf(stdout, FMT_INCORRECT_CLOSE);
    }
    SSL_free(ssl);
  }

  if (serverCert != NULL){
    X509_free (serverCert);
  }

  if (sock != -1){
    close(sock);
  }

  if (ctxSSL != NULL){
    SSL_CTX_free(ctxSSL);
  }
}

int passwordCallback(char *buf, int size, int rwflag, void *password)
{
  strncpy(buf, PASSWORD, size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
#define PORT 50029
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username:\r\n"
#define BAD_USERNAME_MSG "This username exists/empty str is not allowed, enter a different one.\r\n"
#define INVALID_CMD "Invalid command.\r\n"
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client
{
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE];                   // Used to hold input from the client
    char *in_ptr;                           // A pointer into inbuf to help with partial reads
    struct client *next;
};

// Provided functions.
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients.
void announce(struct client *active_clients, char *s)
{

    struct client *cur_client = active_clients; //point to current client
    while (cur_client != NULL)
    {
        //write to socket for this client.
        int cur_sock = cur_client->fd;
        int num;
        num = write(cur_sock, s, strlen(s));
        if (num == -1)
        {
            printf("Removing [%d] from the server\n", cur_sock);
            char goodbye[BUF_SIZE];
            goodbye[0] = '\0';
            strcpy(goodbye, "Goodbye ");
            strcat(goodbye, cur_client->username);
            strcat(goodbye, "\r\n");
            remove_client(&active_clients, cur_sock);
            //since we removed a client, should announce the msg to others:
            announce(active_clients, goodbye);
        }
        //next client
        cur_client = cur_client->next;
    }
}

// Move client c from new_clients list to active_clients list.
void activate_client(struct client *c,
                     struct client **active_clients_ptr, struct client **new_clients_ptr)
{

    struct client **p;
    for (p = new_clients_ptr; *p && (*p)->fd != c->fd; p = &(*p)->next)
        ;
    struct client *t = (*p)->next;
    *p = t;

    c->next = *active_clients_ptr;
    *active_clients_ptr = c;
}

// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails.
fd_set allset;

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr)
{
    struct client *p = malloc(sizeof(struct client));
    if (!p)
    {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;
    for (int i = 0; i < FOLLOW_LIMIT; i++)
    {
        p->followers[i] = NULL;
        p->following[i] = NULL;
    }

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++)
    {
        p->message[i][0] = '\0';
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd)
{
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p)
    {
        // TODO: Remove the client from other clients' following/followers
        // lists
        int p_fd = (*p)->fd;
        struct client *cur_client = *clients;

        //go over all the clients, search through their followers/following lists
        while (cur_client != NULL)
        {
            for (int i = 0; i < FOLLOW_LIMIT; i++)
            {
                //check that they are not NULL.
                if ((cur_client->followers)[i] != NULL && ((cur_client->followers)[i])->fd == p_fd)
                {
                    (cur_client->followers)[i] = NULL;

                    //server log:
                    printf("%s no longer has %s as a follower, because they disconnected\n", 
                    cur_client->username, (*p)->username);
                }
                if ((cur_client->following)[i] != NULL && ((cur_client->following)[i])->fd == p_fd)
                {
                    (cur_client->following)[i] = NULL;

                    //server log:
                    printf("%s is no longer following %s, because they disconnected\n",
                           (*p)->username, cur_client->username);
                }
            }
            cur_client = cur_client->next;
        }

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    }
    else
    {
        fprintf(stderr,
                "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

/*send_function stores a msg of the client in p->message if it has space, otherwise
notify user, that there is not enough space, don't store the msg.
*/
void send_function(struct client *p, char *text, struct client **clients)
{
    int reg = 0;
    for (int i = 0; i < MSG_LIMIT; i++)
    {
        if (strcmp(p->message[i], "") == 0)
        {
            reg = 1;
            //printf("here the message: %s\n", text);
            strcpy(p->message[i], text);
            break;
        }
    }
    if (!reg)
    {
        char *limit = "you have exceed the limit of msgs\n\r";
        if(write(p->fd, limit, strlen(limit)) != -1){

        //server log:
        printf("%s tried to exceed the limit of msgs\n", p->username);
        }
        else
        {
            char msg[BUF_SIZE];
            msg[0]=0;
            strcpy(msg, "Goodbye ");
            strcat(msg, p->username);
            strcat(msg, "\r\n");
            remove_client(clients, p->fd);
            announce(*clients, msg);
        }
        
    }
}

/* shows user the msgs of people, whe he/she follows; types nothing if user doesn't follow anyone.
*/
void show_function(struct client *p, struct client **clients)
{
    int go = 1;
    for (int i = 0; i < FOLLOW_LIMIT; i++)
    {
        if (p->following[i] != NULL && go)
        {
            //go over msg of this i user and write them into socket:
            struct client *user = p->following[i];
            for (int j = 0; j < MSG_LIMIT; j++)
            {
                if (strcmp(user->message[j], "") != 0)
                {
                    char present[BUF_SIZE * 2];
                    present[0] = 0;
                    strcpy(present, user->username);
                    strcat(present, " has written: ");
                    strcat(present, user->message[j]);
                    strcat(present, "\r\n");
                    if (write(p->fd, present, strlen(present)) == -1){
                                    remove_client(clients, p->fd);
                                    go = 0;
                                    break;
                    }
                }
            }
        }
    }
}

/*
p starts following username iff p has enough space to follow people and username has enough space to
be followed; otherwise, make a warning and do not perform an operation.
*/
void follow_function(struct client *p, char *username, struct client **clients)
{

    struct client *cur_client = *clients;
    struct client *temp = NULL;

    // check if client with username exists:
    while (cur_client != NULL)
    {
        if (strcmp(cur_client->username, username) == 0)
        {
            temp = cur_client;
            break;
        }
        cur_client = cur_client->next;
    }

    //client exists:
    if (temp != NULL)
    {
        int check = 0;

        //check if we haven't followed username before
        for (int l = 0; l < FOLLOW_LIMIT; l++)
        {
            if (temp->followers[l] != NULL && (temp->followers[l])->fd == p->fd)
            {
                check = 1;
            }
        }
        // temp_index, p_index - indexes of array where we can store that p follows temp; temp is
        // being followed by p.
        int temp_index = -1;
        int p_index = -1;
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if (temp->followers[i] == NULL && !check)
            {
                for (int j = 0; j < FOLLOW_LIMIT; j++)
                {
                    if (p->following[j] == NULL)
                    {
                        p_index = j;
                        temp_index = i;
                        break;
                    }
                }
            }
            if (p_index != -1)
            {
                break;
            }
        }

        //check if could find the indexes:
        if (p_index != -1)
        {
            p->following[p_index] = temp;
            temp->followers[temp_index] = p;

            //server log:
            printf("%s is following %s\n", p->username, temp->username);
            printf("%s has %s as a follower\n", temp->username, p->username);
        }
        else if (!check)
        {
            char *followers = "You cannot follow more peope or user, you want to follow cannot be followed anymore\r\n";
            printf("Cannot register a following due to Follow_Limit\n");
            if(write(p->fd, followers, strlen(followers)) == -1){
                remove_client(clients, p->fd);
            }
        }

        //check == 1, we already follow the person.
        else
        {
            char *have_already = "You are already following this person\r\n";
            printf("%s is already following %s\n", p->username, temp->username);
            if (write(p->fd, have_already, strlen(have_already))== - 1){
                remove_client(clients, p->fd);
            }
        }
    }

    //bad username, client with such username doesn't exist.
    else
    {
        char *invalid = "Username doesn't exist\r\n";
        printf("Username doesn't exist\n");
        if(write(p->fd, invalid, strlen(invalid)) == -1){
            remove_client(clients, p->fd);
        }
    }
}

/*p stops following username iff p was following username before, otherwise leave a warning that
p wasn't following username before. Remove p from followers of username, remove username from followings of p
Precondition: if p follows username, username has a follower p.
*/
void unfollow_function(struct client *p, char *username, struct client **clients)
{
    struct client *cur_client = *clients;
    struct client *temp = NULL;

    //check if client with username exists:
    while (cur_client != NULL)
    {
        if (strcmp(cur_client->username, username) == 0)
        {
            temp = cur_client;
            break;
        }
        cur_client = cur_client->next;
    }
    if (temp != NULL)
    {

        //check if p follows the person: if so, remove it from the list of followers/followings respectively.
        int found = 0;
        for (int i = 0; i < FOLLOW_LIMIT; i++)
        {
            if (temp->followers[i] != NULL && (temp->followers[i])->fd == p->fd)
            {
                temp->followers[i] = NULL;
                for (int j = 0; j < FOLLOW_LIMIT; j++)
                {
                    if (p->following[j] != NULL && (p->following[j])->fd == temp->fd)
                    {
                        p->following[j] = NULL;
                        found = 1;
                        break;
                    }
                }
                if (found)
                {
                    //server log:
                    printf("%s stoped following %s\n", p->username, temp->username);
                    printf("%s stopped having %s as a follower\n", temp->username, p->username);
                    break;
                }
            }
        }
        if (!found)
        {
            char *msg = "You are not following this person.\r\n";
            if(write(p->fd, msg, strlen(msg)) == -1){
                remove_client(clients, p->fd);
            }

            //server log:
            printf("%s were not following %s, can't unfollow %s\n", p->username, temp->username, temp->username);
        }
    }
    //invalid username:
    else
    {
        char *invalid = "The username you are trying to follow is not active\r\n";
        if(write(p->fd, invalid, strlen(invalid)) == -1){
            remove_client(clients, p->fd);
        }

        //server log:
        printf("The username %s is not active, cannot follow\n", username);
    }
}

int main(int argc, char **argv)
{
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal.
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names).
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or
    // or receive announcements.
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);
    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1)
    {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1)
        {
            perror("select");
            exit(1);
        }
        else if (nready == 0)
        {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset))
        {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd)
            {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1)
            {
                fprintf(stderr,
                        "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be
        // valid.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++)
        {
            if (FD_ISSET(cur_fd, &rset))
            {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next)
                {
                    if (cur_fd == p->fd)
                    {
                        // TODO: handle input from a new client who has not yet
                        // entered an acceptable name
                        //handale partial reads.
                        int room = BUF_SIZE - strlen(p->inbuf);
                        int num_read = read(cur_fd, p->in_ptr, room);
                        if (num_read > 0)
                        {
                            printf("[%d] read %d bytes\n", cur_fd, num_read);

                            //check if we have network newline:
                            if (strstr(p->in_ptr, "\r\n") == NULL)
                            {

                                //point in_ptr to the end of inbuf to prepare for extra reading:
                                int buf_length = strlen(p->inbuf);
                                p->in_ptr = &(p->inbuf[buf_length]);
                            }
                            else
                            {
                                //inbuf has netweork new line:
                                int buf_length = strlen(p->inbuf);
                                p->inbuf[buf_length - 2] = '\0';
                                printf("[%d] Found newline: %s\n",p->fd ,p->inbuf);
                                char name[BUF_SIZE];
                                name[0] = '\0';
                                strcpy(name, p->inbuf);
                                struct client *cur_client = active_clients;

                                //check iff name is valid and none of active_clients have the same username.
                                int check = 1;

                                if (strcmp(name, "") == 0)
                                {
                                    check = 0;
                                }

                                //check the usernames of others
                                while (cur_client != NULL)
                                {
                                    if (strcmp(cur_client->username, name) == 0)
                                    {
                                        check = 0;
                                        break;
                                    }
                                    cur_client = cur_client->next;
                                }
                                if (check)
                                {

                                    //if reached, username is valid, we activate the client:
                                    strcpy(p->username, name);
                                    activate_client(p, &active_clients, &new_clients);
                                    char msg[BUF_SIZE * 2];
                                    msg[0] = '\0';
                                    strcpy(msg, name);
                                    strcat(msg, " has joined the chat\r\n");
                                    announce(active_clients, msg);
                                    printf("%s has joined the chat\n", name);
                                }
                                else
                                {
                                    printf("bad username\n");
                                    char *bad = BAD_USERNAME_MSG;
                                    if(write(cur_fd, bad, strlen(bad)) == -1){
                                        remove_client(&active_clients, cur_fd);
                                    }
                                }

                                //reset the in_ptr and inbuf, to prepare for new line:
                                p->in_ptr = p->inbuf;
                                for (int i = 0; i < BUF_SIZE; i++)
                                {
                                    p->inbuf[i] = 0;
                                }
                            }
                        }

                        //error check num_read for closed socket and internal error
                        else if (num_read == 0)
                        {
                            //if reached: num_read <= 0; remove client, don't notify anyone:
                            printf("[%d] read %d bytes\n", cur_fd, num_read);
                            remove_client(&new_clients, cur_fd);
                        }
                        else{
                            fprintf(stderr, "Read call failed\n");
                            exit(1);
                        }

                        handled = 1;
                        break;
                    }
                }

                if (!handled)
                {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next)
                    {
                        if (cur_fd == p->fd)
                        {
                            // TODO: handle input from an active client
                            int room = BUF_SIZE - strlen(p->inbuf);
                            int num_read = read(cur_fd, p->in_ptr, room);

                            if (num_read > 0)
                            {

                                printf("[%d] read %d bytes\n", cur_fd, num_read);
                                //check for network newline, update the in_ptr:
                                if (strstr(p->in_ptr, "\r\n") == NULL)
                                {
                                    int buf_length = strlen(p->inbuf);
                                    p->in_ptr = &(p->inbuf[buf_length]);
                                }

                                else
                                {
                                    //read input
                                    int buf_length = strlen(p->inbuf);
                                    p->inbuf[buf_length - 2] = '\0';
                                    printf("[%d] Found newline: %s\n", p->fd, p->inbuf);
                                    char msg[BUF_SIZE];
                                    msg[0] = '\0';
                                    strcpy(msg, p->inbuf);

                                    //server log
                                    printf("%s: %s\n", p->username, msg);

                                    char *invalid_cmd = INVALID_CMD;

                                    char *space;
                                    space = strchr(msg, ' ');
                                    if (space == NULL)
                                    {
                                        //either quit, show or invalid command:
                                        if (strcmp(msg, "quit") != 0 && strcmp(msg, "show") != 0)
                                        {
                                            if(write(cur_fd, invalid_cmd, strlen(invalid_cmd))!=-1){
                                            printf("Invalid command.\n");
                                            }
                                            else{
                                                remove_client(&active_clients, p->fd);
                                            }
                                        }
                                        else
                                        {
                                            //quit part:
                                            if (strcmp(msg, "quit") == 0)
                                            {
                                                char goodbye[BUF_SIZE] = {0};
                                                strcpy(goodbye, "Goodbye ");
                                                strcat(goodbye, p->username);
                                                strcat(goodbye, "\r\n");
                                                remove_client(&active_clients, cur_fd);
                                                announce(active_clients, goodbye);
                                            }
                                            //show part:
                                            else
                                            {
                                                show_function(p, &active_clients);
                                            }
                                        }
                                    }

                                    //have space but msg is too short/too long
                                    else if (space - msg > 8 || space - msg < 4)
                                    {
                                        if(write(cur_fd, invalid_cmd, strlen(invalid_cmd)) != -1){
                                        printf("Invalid command.\n");
                                        }
                                        else{
                                            remove_client(&active_clients, cur_fd);
                                        }
                                    }
                                    //reached here, meaning we found the space:
                                    else
                                    {

                                        //split command and the rest of the msg:
                                        char command[BUF_SIZE];
                                        char rest[BUF_SIZE];
                                        command[0] = '\0';
                                        rest[0] = '\0';
                                        strncpy(command, msg, space - msg);
                                        command[space - msg] = '\0';
                                        strncpy(rest, space + 1, strlen(msg) - strlen(command) - 1);
                                        rest[strlen(msg) - strlen(command) - 1] = '\0';

                                        //at this point we have command and we have rest of the text.
                                        if (strcmp(command, "send") == 0)
                                        {
                                            send_function(p, rest, &active_clients);
                                        }
                                        else if (strcmp(command, "follow") == 0)
                                        {
                                            follow_function(p, rest, &active_clients);
                                        }
                                        else if (strcmp(command, "unfollow") == 0)
                                        {
                                            unfollow_function(p, rest, &active_clients);
                                        }
                                        else
                                        {
                                            if(write(cur_fd, invalid_cmd, strlen(invalid_cmd)) != -1){

                                            //server log:
                                            printf("Invalid coomand.\n");
                                            }
                                            else{
                                                remove_client(&active_clients, cur_fd);
                                            }
                                        }
                                    }

                                    //reset the pointer
                                    p->in_ptr = p->inbuf;
                                    for (int i = 0; i < BUF_SIZE; i++)
                                    {
                                        p->inbuf[i] = 0;
                                    }
                                }
                            }
                            else if (num_read == 0)
                            {
                                printf("[%d] read %d bytes\n", cur_fd, num_read);
                                char goodbye[BUF_SIZE] = {0};
                                strcpy(goodbye, "Goodbye ");
                                strcat(goodbye, p->username);
                                strcat(goodbye, "\r\n");
                                remove_client(&active_clients, cur_fd);
                                announce(active_clients, goodbye);

                            }
                            else
                            {
                                fprintf(stderr, "Read call failed\n");
                                exit(1);
                            }
                            
                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFNotificationCenter.h>
#include <AppSupport/CPDistributedMessagingCenter.h>

#include "fishhook.h"

// since this dylib should only be loaded into launchd and xpcproxy
// it's safe to assume that we're in xpcproxy if getpid() != 1
enum currentprocess {
    PROCESS_LAUNCHD,
    PROCESS_XPCPROXY,
};

int current_process = PROCESS_XPCPROXY;

typedef int (*pspawn_t)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], const char* envp[]);

pspawn_t old_pspawn, old_pspawnp;

int fake_posix_spawn_common(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], const char* envp[], pspawn_t old) {
    
    FILE *newf = fopen("/var/log/pspawn.txt", "w+");
    
    fprintf(newf, "PSPAWNP PATH IS %s\n", path);
    //fprintf(newf, "PSPAWNP ARG 0 IS %s\n", argv[0]);
    //fprintf(newf, "PSPAWNP ARG 1 IS %s\n", argv[1]);
    
    fclose(newf);
    
    CPDistributedMessagingCenter *messageCenter = [CPDistributedMessagingCenter centerNamed:@"com.jakeashacks.jbclient"];
    [messageCenter sendMessageAndReceiveReplyName:@"platformize" userInfo:[NSDictionary dictionaryWithObject:[NSString stringWithFormat:@"%d", getpid()] forKey:@"pid"]];
    
   // FILE *new = fopen("/var/log/pld.txt", "w+");
    //extern CFNotificationCenterRef CFNotificationCenterGetDistributedCenter(void);
    
    //CFNotificationCenterPostNotification(CFNotificationCenterGetDistributedCenter(), CFSTR("com.jakeashacks.jailbreakd"), NULL, NULL, kCFNotificationDeliverImmediately);
    
   /* pid_t pd;
    const char* args[] = {"/var/testbin", NULL};
    
    int rv = old(&pd, "/var/testbin", NULL, NULL, (char **)&args, NULL);
    if (!rv) {
        int a;
        waitpid(pd, &a, 0);
    }
    
    fprintf(new, "LAUNCHING... RV = %d", rv);
    fclose(new);*/
    
    int origret = old(pid, path, file_actions, attrp, argv, envp);
    return origret;
}


int fake_posix_spawn(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawn);
}

int fake_posix_spawnp(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawnp);
}


void rebind_pspawns(void) {
    struct rebinding rebindings[] = {
        {"posix_spawn", (void *)fake_posix_spawn, (void **)&old_pspawn},
        {"posix_spawnp", (void *)fake_posix_spawnp, (void **)&old_pspawnp},
    };
    
    rebind_symbols(rebindings, 2);
}

void* thd_func(void* arg){
    NSLog(@"In a new thread!");
    rebind_pspawns();
    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
    /*if (getpid() == 1) {
        current_process = PROCESS_LAUNCHD;
        pthread_t thd;
        pthread_create(&thd, NULL, thd_func, NULL);
    } else {
        current_process = PROCESS_XPCPROXY;*/
    current_process = PROCESS_LAUNCHD;
        rebind_pspawns();
    //}
}

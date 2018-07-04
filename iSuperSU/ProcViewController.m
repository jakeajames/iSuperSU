//
//  ProcViewController.m
//  iSuperSU
//
//  Created by Jake James on 7/1/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "ProcViewController.h"
#include "common.h"

#include <sys/sysctl.h>
#include <mach/mach.h>

NSMutableArray *procs;

NSArray *allProcesses() {
    static int maxArgumentSize = 0;
    if (maxArgumentSize == 0) {
        size_t size = sizeof(maxArgumentSize);
        if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
            perror("sysctl argument size");
            maxArgumentSize = 4096; // Default
        }
    }
    NSMutableArray *processes = [NSMutableArray array];
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *info;
    size_t length;
    int count;
    
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
        return nil;
    if (!(info = malloc(length)))
        return nil;
    if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
        free(info);
        return nil;
    }
    count = (int)length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        size_t size = maxArgumentSize;
        char *buffer = (char *)malloc(length);
        if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
            NSString* executable = @(buffer + sizeof(int));
            uid_t uid = -1;
            struct kinfo_proc process;
            size_t procBufferSize = sizeof(process);
            const u_int pathLenth = 4;
            int path[pathLenth] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
            int sysctlResult = sysctl(path, pathLenth, &process, &procBufferSize, NULL, 0);
            if ((sysctlResult == 0) && (procBufferSize != 0)) {
                uid = process.kp_eproc.e_ucred.cr_uid;
            }
            int user = 0;
            if ([executable hasPrefix:@"/var/"] || [executable hasPrefix:@"/private/var"]) {
                user = 1;
            }
            int appex = 0;
            if ([executable containsString:@".appex/"]) {
                appex = 1;
            }
            [processes addObject:[NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:pid], @"pid", executable, @"executable", [executable lastPathComponent], @"name", [NSNumber numberWithInt:appex], @"appex", [NSNumber numberWithInt:uid], @"uid", [NSNumber numberWithInt:user], @"userapp",  nil]];
        }
        free(buffer);
    }
    free(info);
    return processes;
}

@interface ProcViewController ()
@property (strong, nonatomic) IBOutlet UITableView *procTable;
@end

@implementation ProcViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.procTable.delegate = self;
    self.procTable.dataSource = self;
    if (!procs) procs = [NSMutableArray array];
    [self updateTableView];
}

-(void)viewDidAppear:(BOOL)animated {
   // [self updateTableView];
}

- (void)updateTableView {
    NSArray *p = allProcesses();
    //NSLog(@"All procs: %@", p);
    for (NSDictionary *dict in p) {
        if ([dict objectForKey:@"userapp"] == [NSNumber numberWithInt:1])
            [procs addObject:[NSString stringWithFormat:@"%@ - pid %@", [dict objectForKey:@"name"], [dict objectForKey:@"pid"]]];
        //NSLog(@"name: %@", [dict objectForKey:@"name"]);
    }
    [self.procTable reloadData];
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [procs count];
}


- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"identifier" forIndexPath:indexPath];
    
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"identifier"];
    }
    cell.textLabel.text = [procs objectAtIndex:indexPath.row];
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath; {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"iSuperSU"
                                                                   message:@"Choose an action"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction* root = [UIAlertAction actionWithTitle:@"Fix setuid()" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_FIXUP_SETUID);
        
    }];
    
    UIAlertAction* unsandbox = [UIAlertAction actionWithTitle:@"Unsandbox" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_UNSANDBOX);
    }];
    
    UIAlertAction* csflags = [UIAlertAction actionWithTitle:@"Set csflags" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_ENTITLE);
    }];
    
    UIAlertAction* plat = [UIAlertAction actionWithTitle:@"Platformize" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE);
    }];
    
    UIAlertAction* allinone = [UIAlertAction actionWithTitle:@"All in one" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_FIXUP_SETUID);
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_UNSANDBOX);
        calljailbreakd(atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]), JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE);
    }];
    
    
    UIAlertAction* killit = [UIAlertAction actionWithTitle:@"Kill" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * action) {
        pid_t pid = atoi([[[[procs objectAtIndex:indexPath.row] componentsSeparatedByString:@"- pid "] lastObject] UTF8String]);
        kill(pid, SIGSEGV);
    }];
    
    UIAlertAction* def = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * action) {
    }];
    
    [alert addAction:root];
    [alert addAction:unsandbox];
    [alert addAction:csflags];
    [alert addAction:allinone];
    [alert addAction:killit];
    [alert addAction:def];
    
    [self presentViewController:alert animated:YES completion:nil];
}

/*
// Override to support conditional editing of the table view.
- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    // Return NO if you do not want the specified item to be editable.
    return YES;
}
*/

/*
// Override to support editing the table view.
- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle == UITableViewCellEditingStyleDelete) {
        // Delete the row from the data source
        [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
    } else if (editingStyle == UITableViewCellEditingStyleInsert) {
        // Create a new instance of the appropriate class, insert it into the array, and add a new row to the table view
    }   
}
*/

/*
// Override to support rearranging the table view.
- (void)tableView:(UITableView *)tableView moveRowAtIndexPath:(NSIndexPath *)fromIndexPath toIndexPath:(NSIndexPath *)toIndexPath {
}
*/

/*
// Override to support conditional rearranging of the table view.
- (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath {
    // Return NO if you do not want the item to be re-orderable.
    return YES;
}
*/

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end

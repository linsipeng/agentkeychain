/* Hosted test orchestration only; never packaged as a pilot launcher. */
#define _GNU_SOURCE 1
#define AKC_ROLLBACK_PRIMITIVES_ONLY 1
#include "pilot_sqlite_rollback_writer.c"
#include "../../native/pilot-linux-descriptor-launch.h"
#include "../../native/pilot-linux-peer-frame.h"
#include <inttypes.h>
#include <sys/socket.h>

struct fixture {struct run r;struct stat top,dir,lock,main;};
static struct fixture owned(const char *path,bool create){
 const char *leaf=strrchr(path,'/'),prefix[]="akc-native-installed-";
 CHECK(path[0]=='/'&&leaf&&strncmp(leaf+1,prefix,sizeof prefix-1)==0&&strlen(leaf+1)>sizeof prefix-1);
 struct fixture f={.r={.lease=-1,.fence_fd=-1}};
 f.r.parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 CHECK(f.r.parent>=3&&fstat(f.r.parent,&f.top)==0&&S_ISDIR(f.top.st_mode)&&
  (f.top.st_mode&07777)==0700&&f.top.st_uid==geteuid());
 if(create)CHECK(mkdirat(f.r.parent,"pilot",0700)==0);
 const int directory=openat(f.r.parent,"pilot",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 CHECK(directory>=3&&fstat(directory,&f.dir)==0&&S_ISDIR(f.dir.st_mode)&&
  (f.dir.st_mode&07777)==0700&&f.dir.st_dev==f.top.st_dev&&f.dir.st_uid==f.top.st_uid);
 f.r.scope=(struct scope){directory,f.dir.st_dev,f.dir.st_uid,f.dir.st_ino};
 CHECK(location_matches(&f.r.scope,f.r.parent));
 if(create){
  const int lock=openat(directory,lease_name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  CHECK(lock>=3&&fsync(lock)==0&&fsync(directory)==0);
  close_checked(lock);
 }
 CHECK(fstatat(directory,lease_name,&f.lock,AT_SYMLINK_NOFOLLOW)==0&&matches_lock(&f.r.scope,&f.lock,f.lock.st_ino));
 f.r.lock_inode=f.lock.st_ino;
 return f;
}
static void shut(struct fixture *f){close_checked(f->r.scope.directory);close_checked(f->r.parent);}
static void check_op(const char *op){CHECK(strlen(op)==64&&strspn(op,"0123456789abcdef")==64);}
static sqlite3 *open_writer(struct fixture *f,sqlite3_vfs *v){
 CHECK(acquire(&f->r.scope,f->r.parent,f->r.lock_inode,&f->r.lease)==lease_held);
 *v=(sqlite3_vfs){.iVersion=1,.szOsFile=sizeof(struct file),.mxPathname=128,.zName=vfs_name,.pAppData=&f->r,
  .xOpen=open_file,.xDelete=delete_file,.xAccess=access_file,.xFullPathname=canonical_path,.xRandomness=randomness,
  .xSleep=sleep_for,.xCurrentTime=clock_now};
 sqlite3 *db=NULL;
 CHECK(sqlite3_vfs_register(v,0)==SQLITE_OK&&sqlite3_open_v2(main_name,&db,SQLITE_OPEN_READWRITE|
  SQLITE_OPEN_NOFOLLOW|SQLITE_OPEN_PRIVATECACHE,vfs_name)==SQLITE_OK);
 sql(db,"PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;PRAGMA temp_store=MEMORY;PRAGMA mmap_size=0;");
 CHECK(scalar(db,"PRAGMA synchronous")==3&&scalar(db,"SELECT count(*) FROM pragma_journal_mode WHERE journal_mode='delete'")==1);
 return db;
}
static void close_writer(struct fixture *f,sqlite3_vfs *v,sqlite3 *db){
 CHECK(lease_live(&f->r)&&sqlite3_close(db)==SQLITE_OK&&sqlite3_vfs_unregister(v)==SQLITE_OK&&
  gate_access(&f->r.scope,rollback_name)==0);
 close_checked(f->r.lease);
 f->r.lease=-1;
}
static void execute_pair(sqlite3 *db,const char *query,const char *first,const char *second){
 sqlite3_stmt *s=NULL;
 CHECK(sqlite3_prepare_v2(db,query,-1,&s,NULL)==SQLITE_OK&&sqlite3_bind_text(s,1,first,-1,SQLITE_STATIC)==SQLITE_OK&&
  sqlite3_bind_text(s,2,second,-1,SQLITE_STATIC)==SQLITE_OK&&sqlite3_step(s)==SQLITE_DONE&&
  sqlite3_changes(db)==1&&sqlite3_finalize(s)==SQLITE_OK);
}
static void identities(const struct fixture *f){
 printf("{\"uid\":\"%ju\",\"device\":\"%ju\",\"parent\":\"%ju\",\"directory\":\"%ju\",\"lock\":\"%ju\",\"main\":\"%ju\"}\n",
  (uintmax_t)f->dir.st_uid,(uintmax_t)f->dir.st_dev,(uintmax_t)f->top.st_ino,(uintmax_t)f->dir.st_ino,
  (uintmax_t)f->lock.st_ino,(uintmax_t)f->main.st_ino);
}
static void seed(struct fixture *f,const char *op,const char *frame,const char *receipt){
 check_op(op);
 CHECK(*frame&&*receipt&&strlen(frame)<=512&&strlen(receipt)<=1024);
 CHECK(acquire(&f->r.scope,f->r.parent,f->r.lock_inode,&f->r.lease)==lease_held);
 sqlite3 *memory=NULL;
 CHECK(sqlite3_open(":memory:",&memory)==SQLITE_OK);
 sql(memory,"CREATE TABLE snapshot(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL,operation TEXT NOT NULL,frame TEXT NOT NULL);"
  "CREATE TABLE receipt(generation INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,canonical TEXT NOT NULL);"
  "CREATE TRIGGER no_receipt_update BEFORE UPDATE ON receipt BEGIN SELECT raise(ABORT,'receipt immutable');END;"
  "CREATE TRIGGER no_receipt_delete BEFORE DELETE ON receipt BEGIN SELECT raise(ABORT,'receipt immutable');END;");
 sqlite3_int64 bytes=0;
 unsigned char *data=sqlite3_serialize(memory,"main",&bytes,0);
 CHECK(data&&bytes>0&&bytes<=maximum);
 const int file=gate_open(&f->r.scope,main_name,true,true);
 CHECK(file>=3);
 for(sqlite3_int64 off=0;off<bytes;){
  const ssize_t n=write(file,data+off,(size_t)(bytes-off));
  if(n<0&&errno==EINTR)continue;
  CHECK(n>0);
  off+=n;
 }
 CHECK(fstat(file,&f->main)==0&&fsync(file)==0&&fsync(f->r.scope.directory)==0);
 close_checked(file);
 sqlite3_free(data);
 CHECK(sqlite3_close(memory)==SQLITE_OK);
 close_checked(f->r.lease);
 f->r.lease=-1;
 sqlite3_vfs v;
 sqlite3 *db=open_writer(f,&v);
 sql(db,"BEGIN IMMEDIATE");
 execute_pair(db,"INSERT INTO snapshot VALUES(1,1,?,?)",op,frame);
 execute_pair(db,"INSERT INTO receipt VALUES(1,?,?)",op,receipt);
 sql(db,"COMMIT");
 close_writer(f,&v,db);
 identities(f);
}
static void tamper(struct fixture *f,const char *op,const char *expected){
 check_op(op);
 CHECK(*expected&&strlen(expected)<=512);
 struct stat before,after;
 CHECK(fstatat(f->r.scope.directory,main_name,&before,AT_SYMLINK_NOFOLLOW)==0&&allowed_stat(&f->r.scope,&before));
 sqlite3_vfs v;
 sqlite3 *db=open_writer(f,&v);
 sql(db,"BEGIN IMMEDIATE");
 execute_pair(db,"UPDATE snapshot SET frame='synthetic-wrong-frame' WHERE id=1 AND generation=1 AND operation=? AND frame=?",op,expected);
 sql(db,"COMMIT");
 close_writer(f,&v,db);
 CHECK(fstatat(f->r.scope.directory,main_name,&after,AT_SYMLINK_NOFOLLOW)==0&&allowed_stat(&f->r.scope,&after)&&before.st_ino==after.st_ino);
}
static int nybble(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static int take_status(pid_t child){
 int status;
 for(int i=0;i<400;i++){
  const pid_t got=waitpid(child,&status,WNOHANG);
  if(got==child)return WIFEXITED(status)?WEXITSTATUS(status):-1;
  CHECK(got==0||(got<0&&errno==EINTR));
  const struct timespec pause={.tv_nsec=10000000};
  (void)nanosleep(&pause,NULL);
 }
 (void)kill(child,SIGKILL);
 while(waitpid(child,NULL,0)<0&&errno==EINTR){}
 return -1;
}
static int read_one(struct fixture *f,const char *image_hash){
 check_op(image_hash);
 unsigned char digest[32];
 for(size_t i=0;i<sizeof digest;i++)digest[i]=(unsigned char)((nybble(image_hash[2*i])<<4)|nybble(image_hash[2*i+1]));
 unsigned char req[AKC_PILOT_PEER_MAX_FRAME+1],reply[AKC_PILOT_PEER_MAX_FRAME];
 const size_t n=fread(req,1,sizeof req,stdin);
 CHECK(!ferror(stdin)&&feof(stdin)&&n>0&&n<=AKC_PILOT_PEER_MAX_FRAME);
 const int image=openat(f->r.parent,"reader",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 CHECK(image>=3);
 int pair[2];
 CHECK(akc_pilot_peer_pair(pair)==0&&pair[0]>=3&&pair[1]>=3);
 struct sigaction inherited;
 CHECK(sigaction(SIGCHLD,NULL,&inherited)==0&&inherited.sa_handler==SIG_DFL&&!(inherited.sa_flags&SA_NOCLDWAIT));
 const pid_t pid=fork();
 CHECK(pid>=0);
 if(pid==0){
  close_checked(pair[0]);
  int inputs[]={pair[1],f->r.parent,f->r.scope.directory};
  for(int i=0;i<3;i++){
   const int staged=fcntl(inputs[i],F_DUPFD_CLOEXEC,10);
   if(staged<0||dup2(staged,i)!=i)_exit(90);
   if(close(staged)!=0)_exit(90);
  }
  (void)akc_pilot_linux_exec_verified_fd(image,digest);
  _exit(91);
 }
 close_checked(pair[1]);
 close_checked(image);
 ssize_t answer=-1;
 if(akc_pilot_peer_send(pair[0],req,n)==0){
  const struct akc_pilot_peer expected={.pid=pid,.uid=getuid(),.gid=getgid()};
  answer=akc_pilot_peer_recv(pair[0],expected,reply,sizeof reply);
 }
 close_checked(pair[0]);
 const int result=take_status(pid);
 if(result==78||result==79)return answer<0?result:92;
 if(result!=0||answer<=0)return 92;
 return fwrite(reply,1,(size_t)answer,stdout)==(size_t)answer&&fflush(stdout)==0?0:93;
}
int main(int argc,char **argv){
 CHECK(argc>=3&&getuid()!=0&&getuid()==geteuid()&&getgid()==getegid()&&
  fcntl(0,F_GETFD)>=0&&fcntl(1,F_GETFD)>=0&&fcntl(2,F_GETFD)>=0&&
  sqlite3_libversion_number()==3054001&&!strcmp(sqlite3_sourceid(),sqlite_source));
 umask(077);
 const bool create=!strcmp(argv[1],"prepare");
 CHECK((create&&argc==3)||(!strcmp(argv[1],"seed")&&argc==6)||
  (!strcmp(argv[1],"tamper")&&argc==5)||(!strcmp(argv[1],"read")&&argc==4));
 struct fixture f=owned(argv[2],create);
 int result=0;
 if(create)identities(&f);
 else if(!strcmp(argv[1],"seed"))seed(&f,argv[3],argv[4],argv[5]);
 else if(!strcmp(argv[1],"tamper"))tamper(&f,argv[3],argv[4]);
 else result=read_one(&f,argv[3]);
 shut(&f);
 return result;
}

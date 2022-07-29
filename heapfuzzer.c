/*
	By Sirus Shahini
	~cyn
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pthread.h>

#define MAX_SEQ_LEN 10

pthread_t watch_thread;

int sequence_lengths[] = {6,7,8};
int alloc_class_sz = 1;
int num_of_made_alloc = 0;
int non_alloc_count = 0;
char non_allocs[] = {'F','O'};
int shutdown = 0;


int allocation_sizes[]={0x8};
int overflow_sizes[]={1};
struct size_classes{
	int allocate[1] ;
	int overflow[1] ;

}sz_class;


unsigned long total_generated;
unsigned long part_generated;

struct alloc_data{
	unsigned long adr;
	unsigned long size;
	int freed;
};
struct overflow_data{
	int of_size;
}overflows[MAX_SEQ_LEN];

typedef struct {
	char *data;
	int len;
	int **descriptor;
	int non_alloc_len;
} sequence_container;


int main_pid;
int evaluator_count = 2;
int eval_pids[32];
int current_evaluator=0;
struct evaluators_board{
	void *shm;
	int current_seq;
	int running;
	int pid;
	int running_seq;
	int last_start_index;
	int poc_index;
}*eval_boards;
int my_eval_id;

unsigned long free_list[10];
int free_list_index = 0;

#define BLOCKS_NUM 1000

#define LINEAR_SEQ_SIZE 10*10


struct eval_block{
	char dummy[LINEAR_SEQ_SIZE];
};


int _log=0;
void cprint(char *fmt, ...){
	if (!_log) return;
	va_list argp;
	va_start(argp,fmt);
	vprintf(fmt,argp);
	va_end(argp);
}

void cexit(int e,int child, char *msg){
	char p[6];
	if (e==0){
		strcpy(p,(child ? "Child" : "Main"));
		printf("[>] %s exiting normally\n",p);
	}else{
		strcpy(p,(child ? "Child" : "Main"));
		printf("[!] %s: %s\n",p,msg);
	}
	exit(e);
}



void eval_engine_indexes(sequence_container *);
void eval_engine_o(sequence_container *);
void eval_engine_finalize(sequence_container *,int);
void evaluator_start();

void print_exec_sequence(sequence_container *seq){
	int i;

	printf("[");
	for (i=0;i<seq->len;i++){
		printf("%c:",seq->data[i]);
		switch (seq->data[i]){
		case 'A':
			printf("%d ",*seq->descriptor[i]);
			break;
		case 'F':
			if (seq->descriptor[i])
				printf("%d ",(seq->descriptor[i])[0]);
			break;
		case 'O':
			if (seq->descriptor[i]){
			    printf("%d,",(seq->descriptor[i])[0]);
			    printf("%d ",(seq->descriptor[i])[1]);
			}
			break;

		}

	}
	printf("]");
	if (part_generated%3==0)printf("\n");
	else printf("\t");
}


void exec_sequence(sequence_container *seq){
	int i;
	int alloc_count = seq->len - seq->non_alloc_len;
	struct alloc_data *allocs = malloc(alloc_count*sizeof(struct alloc_data));
	void *alloc_adr;
	int a_index=0;

	for (i=0;i<seq->len;i++){

		switch (seq->data[i]){
		case 'A':
			alloc_adr = malloc(*seq->descriptor[i]);
			allocs[a_index].adr = (unsigned long)alloc_adr;
			allocs[a_index++].size = *seq->descriptor[i];
			printf("Allocated 0x%016lx with size %d\n",alloc_adr,*seq->descriptor[i]);
			break;
		case 'F':
			free((void *)allocs[*seq->descriptor[i]].adr);
			printf("Freed %d 0x%016lx \n",*seq->descriptor[i],allocs[*seq->descriptor[i]].adr);
			break;
		case 'O':
			memset((void *)allocs[*seq->descriptor[i]].adr,0,allocs[*seq->descriptor[i]].size + seq->descriptor[i][1]);
			printf("Overflowed %d 0x%016lx %d\n",*seq->descriptor[i],allocs[*seq->descriptor[i]].adr,seq->descriptor[i][1]);
			break;

		}

	}
	cexit(0,1,0);
}


int eval_filter(sequence_container *seq){

	return 1;
}


void build_desc(sequence_container *seq,int *locs,int locs_len,char op){
	int i;
	int c_a=0;
	int **desc = seq->descriptor;

	switch (op){
	case 'A':

		for (i=0;i<seq->len;i++){
			if (seq->data[i]=='A'){
			    if (!desc[i]) desc[i]=malloc(sizeof(int));
			    *desc[i]=sz_class.allocate[locs[c_a++]];


			}
		}
		break;
	case 'I':

		for (i=0;i<seq->len;i++){
			if (seq->data[i]=='F'){
			    if (!desc[i]) desc[i]=malloc(sizeof(int));
			    *desc[i]=locs[c_a++];
			    //printf("%d ",*desc[i]);
			}else if(seq->data[i]=='O'){
			    if (!desc[i]) desc[i]=malloc(sizeof(int)*2);
			    (desc[i][0])=locs[c_a++];
			}
		}
		break;
	case 'O':
		for (i=0;i<seq->len;i++){
			if (seq->data[i]=='O'){
			    (desc[i][1])=sz_class.overflow[locs[c_a++]];
			}
		}
		break;
	}

}
/*
	Stage 1: describe allocation sizes
*/
void eval_engine_start(sequence_container *seq){
	int *locs;
	int i;
	int last_locs_index;
	int last_collection_val;
	int alloc_count;

	if (!eval_filter(seq)) return;


	alloc_count = seq->len - seq->non_alloc_len;
	locs = malloc(alloc_count*sizeof(int));
	memset(locs,0,alloc_count*sizeof(int));
	last_locs_index = alloc_count -1;
	last_collection_val = (sizeof(sz_class.allocate)/sizeof(sz_class.allocate[0])) - 1;

	while(1){


		build_desc(seq,locs,alloc_count,'A');

		eval_engine_indexes(seq);

		if (locs[last_locs_index] == last_collection_val){
			locs[last_locs_index]=0;
			for (i=last_locs_index-1;i>-1;i--){
			    if (locs[i]<last_collection_val){
			        locs[i]++;
			        break;
			    }else{
			        locs[i]=0;
			    }
			}
			if (i==-1)
			    break;
		}else{
			locs[last_locs_index]++;
		}
	}
	free(locs);

}
int set_if_sane(int *loc,int a_place_index,int *a_places,int *n_a_places,int n_a_place_index){
	*loc = a_place_index;

	if (a_places[a_place_index] < n_a_places[n_a_place_index]){
		return 1;
	}
	return 0;
}
/*
	Stage 2: describe F and O
*/
void eval_engine_indexes(sequence_container *seq){
	int *locs;
	int i;
	int last_locks_index;
	int last_collection_val;
	int *alloc_places;
	int *non_alloc_places;
	int alloc_count;
	int a_index=0;
	int n_index=0;
	int is_sane=1;

	if (!eval_filter(seq)) return;


	alloc_count = seq->len - seq->non_alloc_len;
	locs = malloc(seq->non_alloc_len*sizeof(int));
	non_alloc_places = malloc(seq->non_alloc_len*sizeof(int));
	alloc_places = malloc(alloc_count*sizeof(int));

	memset(locs,0,seq->non_alloc_len*sizeof(int));
	last_locks_index = seq->non_alloc_len -1;
	last_collection_val = (seq->len - seq->non_alloc_len) - 1;


	for (i=0;i<seq->len;i++){
		if (seq->data[i] == 'A'){
			alloc_places[a_index++] = i;
		}else{
			non_alloc_places[n_index++] = i;
		}
	}
	while(1){

		if (is_sane){
			build_desc(seq,locs,alloc_count,'I');

			eval_engine_o(seq);
		}

		if (locs[last_locks_index] == last_collection_val){

			locs[last_locks_index]=0;
			for (i=last_locks_index-1;i>-1;i--){
			    if (locs[i]<last_collection_val){
			        is_sane = set_if_sane(&locs[i],locs[i]+1,alloc_places,non_alloc_places,i);
			        if (!is_sane){

			            if (locs[i]<last_collection_val){
			                locs[i]++;
			            }else{
			                locs[i] = 0;
			            }
			            continue;
			        }
			        break;
			    }else{
			        locs[i]=0;
			    }
			}
			if (i==-1)
			    break;
		}else{
			is_sane = set_if_sane(&locs[last_locks_index],locs[last_locks_index]+1,alloc_places,non_alloc_places,last_locks_index);
			if (!is_sane){

			    locs[last_locks_index] = last_collection_val;
			}
		}
	}
	free(locs);
	free(alloc_places);
	free(non_alloc_places);


}

/*
	stage 3: describe overflow sizes
*/

void eval_engine_o(sequence_container *seq){
	int *locs;
	int i;
	int last_locks_index;
	int last_collection_val;
	int o_count=0;
	int c_o=0; /* Current overflow */

	if (!eval_filter(seq)) return;


	for (i=0;i<seq->len;i++){
		if (seq->data[i]=='O'){
			o_count++;
		}
	}
	if (o_count<1) {
		eval_engine_finalize(seq,0);
		return;
	}
	locs = malloc(o_count*sizeof(int));
	memset(locs,0,o_count*sizeof(int));
	last_locks_index = o_count -1;
	last_collection_val = (sizeof(sz_class.overflow)/sizeof(sz_class.overflow[0])) - 1;

	while(1){


		build_desc(seq,locs,o_count,'O');
		eval_engine_finalize(seq,0);


		/* Next */
		if (locs[last_locks_index] == last_collection_val){
			locs[last_locks_index]=0;
			for (i=last_locks_index-1;i>-1;i--){
			    if (locs[i]<last_collection_val){
			        locs[i]++;
			        break;
			    }else{
			        locs[i]=0;
			    }
			}
			if (i==-1)
			    break;
		}else{
			locs[last_locks_index]++;
		}
	}
	free(locs);


}
void engine_execute(sequence_container *seq){



}

void copy_seq(void *dst, sequence_container *seq){
	int i;

	*(int *)dst = seq->len;
	dst+=4;
	*(int *)dst = seq->non_alloc_len;
	dst+=4;
	for (i=0;i<seq->len;i++){
		//printf("%c:",seq->data[i]);
		switch (seq->data[i]){
		case 'A':
			*((char*)dst) = 'A';
			dst++;
			*((int*)dst) = *seq->descriptor[i];
			dst+=4;
			break;
		case 'F':
			*((char*)dst) = 'F';
			dst++;
			*((int*)dst) = *seq->descriptor[i];
			dst+=4;
			break;
		case 'O':
			*((char*)dst) = 'O';
			dst++;
			*((int*)dst) = *seq->descriptor[i];
			dst+=4;
			*((int*)dst) = seq->descriptor[i][1];
			dst+=4;
			break;
		default:
			printf("[!] Invalid memory content.");exit(0);
		}
	}
	*(char *)dst = -1;

}
void print_seq_linear(void *dst){
	int i;
	char op;
	int meta,meta2;
	int len;
	int non_alloc_len;

	len = *(int *)dst;
	dst+=4;
	non_alloc_len = *(int *)dst;
	dst+=4;

	printf("[");
	while(1){
		op = *(char *)dst;
		if (op==-1) {printf("]\n"); return;}
		printf("%c",op);
		dst++;

		switch (op){
		case 'A':
			meta = *((int*)dst);
			dst+=4;
			printf(":%d ",meta);

			break;
		case 'F':
			meta = *((int*)dst);
			dst+=4;
			printf(":%d ",meta);

			break;
		case 'O':
			meta = *((int*)dst);
			dst+=4;
			meta2 = *((int*)dst);
			dst+=4;
			printf(":%d,%d ",meta,meta2);
			break;
		default:
			printf("[!] (print linear) Evaluator %d Unknown byte %x\n",op);
			kill(getppid(),SIGUSR2);
			exit(-1);
		}
	}

}

void build_chunk(void *dst,char *code_s,int *var_index,int last_seq){
	int i;
	char op;
	int meta,meta2;
	int len;
	int non_alloc_len;
	char tmp_s[512];
	char print_s[1024];
	int alloc_vars_indexes[20];
	int alloc_sizes[20];
	int a_index=0;
	void *save_dst = dst;

	print_s[0]=0;
	len = *(int *)dst;
	dst+=4;
	non_alloc_len = *(int *)dst;
	dst+=4;

	while(1){
		op = *(char *)dst;
		if (op==-1) {
			if (last_seq){
				strcat(code_s,print_s);
				sprintf(tmp_s,"\n\treturn 0;\n}\n");
				strcat(code_s,tmp_s);
			}

			printf("\n");
			return;
	   	}

		dst++;

		switch (op){
		case 'A':
			meta = *((int*)dst);
			dst+=4;

			alloc_vars_indexes[a_index] = *var_index;
			alloc_sizes[a_index] = meta;

			sprintf(tmp_s,"\tvoid *var%d;\n",*var_index,meta);
			strcat(code_s,tmp_s);
			sprintf(tmp_s,"\tvar%d=malloc(%d);\n",*var_index,meta);
			strcat(code_s,tmp_s);
			if (last_seq){
				sprintf(tmp_s,"\tprintf(\"var%d = 0x%%016lX - 0x%%016lX\\n\",(unsigned long)var%d,((unsigned long)var%d)+%d);\n" ,
				*var_index,*var_index,*var_index,meta);
				strcat(print_s,tmp_s);
			}

			a_index++;
			(*var_index)++;

			break;
		case 'F':
			meta = *((int*)dst); //index
			dst+=4;

			sprintf(tmp_s,"\tfree(var%d);\n",alloc_vars_indexes[meta]);
			strcat(code_s,tmp_s);
			if (last_seq){
				sprintf(tmp_s,"\tprintf(\"Freed var%d\\n\");\n",alloc_vars_indexes[meta]);
				strcat(print_s,tmp_s);
			}
			break;
		case 'O':
			meta = *((int*)dst); //index
			dst+=4;
			meta2 = *((int*)dst); //size
			dst+=4;

			sprintf(tmp_s,"\tmemset((void *)((unsigned long)(var%d) + 0x8),0x11,%d);\n",alloc_vars_indexes[meta],meta2);
			strcat(code_s,tmp_s);
			break;
		default:
			printf("[!] (build_chunk) Evaluator %d Unknown byte %c\n",op);
			kill(getppid(),SIGUSR2);
			exit(-1);
		}
	}



}

void shutdown_other_evals(){
	int i;
	for (i=0;i<evaluator_count;i++){
		printf("Killing %d\n",eval_boards[i].pid);
		kill(eval_boards[i].pid,SIGTERM);
	}
	printf("[>] Killed evluator agents\n");
}
void build_poc(int eval_index){

	int i;
	struct evaluators_board* my_board;
	struct eval_block* blocks;
	char code_chunk[1000];
	int var_index = 0;
	FILE *poc;
	char file_name[255];
	char cmd[1000];

	char POC_TEMPLATE[]="/* \n"
	"	Auto genrated Proof of Concept Code\n"
	"	Sirus Sh (~cyn)\n"
	"*/\n"
	"\n"
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n"
	"#include <string.h>\n"
	"\n"
	"int main(void){\n"
	"";

	my_board = &eval_boards[eval_index];

	sprintf(file_name,"results/poc_%d_%d.c",eval_index,my_board->poc_index++);

	poc = fopen(file_name,"w");
	if (poc==0) {
		printf("HERE\n");
		printf("[!] Can't open %s for writing poc\n",file_name);
		kill(getppid(),SIGUSR2);
		exit(-1);
	}
	fwrite(POC_TEMPLATE,1,strlen(POC_TEMPLATE),poc);


	blocks = (struct eval_block*)my_board->shm;

	/* we write the for loop this way to skip a problematic seq after respawning */
	for (i=my_board->last_start_index;i<my_board->running_seq;i++){
		code_chunk[0]=0;
		build_chunk(&blocks[i],code_chunk,&var_index,i==(my_board->running_seq-1));
		fwrite(code_chunk,1,strlen(code_chunk),poc);
	}
	printf("\033[32m[>] \033[0m Wrote from %d to %d\n",my_board->last_start_index,my_board->running_seq);
  	fclose(poc);

}
int in_free_list(unsigned long adr){
	int i;
	for (i=0;i<free_list_index;i++){
		if (adr == free_list[i])
			return 1;
	}
	return 0;
}
void set_free_allocs(unsigned long adr,struct alloc_data *allocs, int len){
	int i;

	//free_list[free_list_index++] = adr;
	for (i=0;i<len;i++){
		if (allocs[i].adr == adr)
			allocs[i].freed = 1;
	}
}
void remove_from_free_list(unsigned long adr){
	int i;
	for (i=0;i<free_list_index;i++){
		if (adr == free_list[i])
			free_list[i]=0;
	}
}
/*
	check the last allocation against the previous ones
	In case of an anomaly the evaluator exits here.
*/
void evaluate_exec(struct alloc_data *allocs,int last_index,void *dst,int eval_index){
	int i=0;
	int index =0;
	int j;

	unsigned long mem_start = allocs[last_index].adr;
	unsigned long mem_end = mem_start + allocs[last_index].size -1 ;

	for (i=0;i<last_index;i++){
		if (allocs[i].freed) continue;

		if (( mem_start >= allocs[i].adr && mem_start < (allocs[i].adr + allocs[i].size) ) ||
			( mem_end >= allocs[i].adr && mem_end < (allocs[i].adr + allocs[i].size) )
		){

			/*
				Note that since there is a heap corruption at this point,
				any further operation is not reliable.
				FIXME: It's better to ask the main process to build the poc.
			*/

			build_poc(eval_index);
			printf("[>] For ");
			print_seq_linear(dst);
			printf("\t \033[33m[>] \033[0m Found overlap index %d with index %d\n",last_index,i);

			for (j=0;j<=last_index;j++){
				printf("\t\t \033[01;31m%d:%016lx-%016lx %s\033[0m\n",j,allocs[j].adr,allocs[j].adr + allocs[j].size - 1,(allocs[j].freed ? "FREE" : "ALLOCATED"));
			}

			exit(0);
			break;

		}
	}

}


void exec_seq_linear(void *dst,int eval_index){

	void *orig_seq = dst;
	int i;
	char op;
	int meta,meta2;
	int alloc_count ;
	struct alloc_data *allocs;
	int len;
	int non_alloc_len;

	void *alloc_adr;
	int a_index=0;



	len = *(int *)dst;
	dst+=4;
	non_alloc_len = *(int *)dst;
	dst+=4;
	alloc_count = len - non_alloc_len;
	free_list_index = 0;

	allocs = malloc(alloc_count*sizeof(struct alloc_data));


	while(1){
		op = *(char *)dst;

		if (op==-1){

		 	return;
		}
		dst++;

		switch (op){
		case 'A':
			meta = *((int*)dst);
			dst+=4;

			alloc_adr = malloc(meta);

			if (!alloc_adr) cexit(-1,0,"Allocation failed");
			allocs[a_index].adr = (unsigned long)alloc_adr;

			allocs[a_index].size = meta;
			allocs[a_index].freed = 0;


			if (a_index>0) evaluate_exec(allocs,a_index,orig_seq,eval_index);

			//printf("Allocated 0x%016lx-0x%016lx with size %d\n",allocs[a_index].adr,allocs[a_index].adr+allocs[a_index].size-1,meta);

			a_index++;
			break;
		case 'F':
			meta = *((int*)dst); //index
			dst+=4;
			free((void *)allocs[meta].adr);
			set_free_allocs(allocs[meta].adr,allocs,a_index);
			//allocs[meta].freed = 1;
			//printf("Freed %d 0x%016lx \n",meta,allocs[meta].adr);

			break;

		case 'O':
			meta = *((int*)dst);
			dst+=4;
			meta2 = *((int*)dst);
			dst+=4;
			if (meta2==0){
				print_seq_linear(orig_seq);
				kill(getppid(),SIGTERM);
				exit(0);
			}

			memset((void *)(allocs[meta].adr + 0x8 ),0x11,meta2); //chunk + 8 = tcache.key

			break;
		default:
			printf("[!] (exec linear) Evaluator %d Unknown byte: %x [%s]\n",eval_index,op,orig_seq);
			/*
				Fatal state, ask the main process to shutdown.
			*/
			kill(getppid(),SIGUSR2);
			exit(-1);
		}
	}
	free(allocs);

}

/*
	Add the seq to the board for execution by an evaluator
*/
void eval_engine_finalize(sequence_container *seq,int test){
	int i;
	int found=0;
	/*
		Before we send this final sequence to be executed
		we need to exclude not inreseting cases.
		These cases include:
			a) extra free and overflow steps
			b) sane and normal sequences
		finding the second case is a little bit hard. For this
		case we may be able to use regular expression to find
		some obviously sane sequenses. Such sequences will not
		trigger any violation.
	*/
	if (!eval_filter(seq)) return;
	part_generated++;

	print_exec_sequence(seq);

	struct eval_block *e;

	/* Find and idle evaluator */
	while (!found){

		for (i=0;i<evaluator_count;i++){
			if (eval_boards[i].running == 0){
				if (test){print_exec_sequence(seq); printf("\n");}
			    found = 1;
			    e = &((struct eval_block *)(eval_boards[i].shm))[eval_boards[i].current_seq++];
			    //memcpy(&e->seq , seq , sizeof(sequence_container));
			    copy_seq(e,seq);

			    //printf("Found idle %d shm %016lx stored %d %d \n",i,eval_boards[i].shm,eval_boards[i].current_seq,eval_boards[i].pid);
			    if (eval_boards[i].current_seq == BLOCKS_NUM){
			        //printf("Sent signal to %d %d\n",i,eval_boards[i].pid);
			        kill(eval_boards[i].pid,SIGUSR1);
			        eval_boards[i].running = 1;

			    }

			    break;
			}
		}

	}

	//cexit(0,0,0);
}


void eval_run_queue(int eval_index){
	struct evaluators_board* my_board;
	struct eval_block* blocks;
	int i;

	my_board = &eval_boards[eval_index];

	blocks = (struct eval_block*)my_board->shm;

	my_board->last_start_index = my_board->running_seq;

	for (i=my_board->running_seq,my_board->running_seq++;i<my_board->current_seq;my_board->running_seq++){
		exec_seq_linear(&blocks[i],eval_index);

		i = my_board->running_seq;
	}

	/*
		Let main know you're idle now.
	*/

   	my_board->current_seq = 0;
   	my_board->running = 0;
   	my_board->running_seq = 0;
}
/*
	Evaluator specific function
	This must not return to the caller.
*/
void evaluator_start(int id){
	sigset_t sigset;
	int rec_sig;
	struct evaluators_board* my_board;
	struct eval_block* blocks;
	int i;
	my_eval_id = id;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGUSR2);

	sigprocmask(SIG_BLOCK,&sigset,0);
	my_board = &eval_boards[id];
	blocks = (struct eval_block*)my_board->shm;
	close(2);

	if (my_board->running == 1){
		my_board->pid = getpid();
		if (my_board->running_seq < BLOCKS_NUM){
			eval_run_queue(id);
		}else {
			/*
				announce as idle
			*/

			my_board->current_seq = 0;
		   	my_board->running = 0;
		   	my_board->running_seq = 0;
		}
	}

	while(1){
		sigwait(&sigset,&rec_sig);
		if (rec_sig == SIGUSR1){

			cprint("Evaluator %d received START signal\n",id);
			if (my_board->current_seq == 0) continue;

			eval_run_queue(id);

		}else if (rec_sig == SIGUSR2){
			cprint("Evaluator %d received EXIT signal\n",id);
			exit(0); //Don't return
		}
		else{
			printf("Evaluator %d received unwanted start signal %d\n",rec_sig);

		}

	}
	exit(0);
}

unsigned long fact(int x){
	unsigned long r=1;
	while (x) r*=x--;
	return r;
}
void print_combinations(int *choices,unsigned long comb_len){
	unsigned long count;
	int i;

	count = *(unsigned long*)choices;
	cprint("[>] Printing total %d\n",count);
	for (i=0;i<count;i++){
		int j;
		int *adr ;
		printf("%d:",(i+1));
		for (j=0,adr=&choices[2+(i*comb_len)];j<comb_len;j++){
			cprint("%d,",adr[j]);
		}
		cprint("\n");
	}

}
int  *combinations(int *collection,int tot_len,int comb_len,unsigned long *comb_count){
	int *choices;
	unsigned long total_combs;
	int *locs;
	int i;
	int added = 0;

	total_combs = fact(tot_len)/(fact(tot_len-comb_len)*fact(comb_len));
	*comb_count = total_combs;
	choices = malloc((total_combs+2)*comb_len*sizeof(int));

	*(unsigned long*)choices = total_combs;
	locs=malloc(comb_len*sizeof(int));
	added=2;
	for (i=0;i<comb_len;i++){
		locs[i]=i;
	}
	int c=0;

	while (1){
		/* add this choice */
		for (i=0;i<comb_len;i++){
			choices[added++] = collection[locs[i]];

		}
		if (locs[comb_len-1]==tot_len-1){
			int last_col_index = tot_len-1;
			int last_comb_index = comb_len-1;
			for (i=1;i<comb_len;i++){
			    int check_index=last_comb_index-i;
			    if (last_col_index-locs[check_index] > i){
			        int j;
			        locs[check_index]++;
			        for (j=check_index+1;j<comb_len;j++){

			            locs[j]=locs[j-1]+1;
			        }

			        break;
			    }
			}

			if (i==comb_len)
			    break;
		}else
			locs[comb_len-1]++;


	}
	free(locs);

	return choices;
}

void print_sequence(sequence_container *seq){
	int i;
	for (i=0;i<seq->len;i++){
		printf("%c",seq->data[i]);
	}
	printf("\n");
}
char *init_sequence(sequence_container *seq,int len, int non_alloc_len){
	int i;
	char *tmp_sq = malloc(len);
	seq->len = len;
	seq->data = tmp_sq;
	seq->descriptor = malloc(len*sizeof(void *));
	seq->non_alloc_len = non_alloc_len;
	for (i=0;i<len;i++){
		tmp_sq[i] = '-'; /* empty cell */
		seq->descriptor[i] = 0;
	}

	return tmp_sq;
}

void destruct_seq(sequence_container *seq){
	int i;
	free(seq->data);
	for (i=0;i<seq->len;i++){
		if (seq->descriptor[i])
			free(seq->descriptor[i]);
	}
	free(seq->descriptor);
}

void build_permutations(int *choice,int total_len,int comb_len){
	int i;
	char *locs;
	int non_alloc_last_index = (sizeof(non_allocs)/sizeof(non_allocs[0]))-1; //last non-alloc candidate in non_allocs array
	sequence_container seq;
	char *sequence; /* actual allocation string */
	init_sequence(&seq,total_len,comb_len);
	sequence = seq.data;

	locs = malloc(sizeof(char)*comb_len);
	memset(locs,0,sizeof(char)*comb_len);
	while(1){
		/*
			Build a sequence here
			We fill the chosen cells (based on choice[]) with non_allocs
			array indices. Starting from all zeros.
		*/
		for (i=0;i<comb_len;i++){
			sequence[choice[i]] = non_allocs[locs[i]];
		}
		for (i=0;i<total_len;i++){
			if (sequence[i]=='-'){
			    sequence[i]='A';
			}
		}

		if (strstr(sequence,"AA") || strstr(sequence,"O")) //Ignore sane cases FIXME
			eval_engine_start(&seq);

		if (locs[comb_len-1]==non_alloc_last_index){
			for (i=comb_len-1;i>-1;i--){
			    if (locs[i]==non_alloc_last_index){
			        locs[i]=0;
			        if (i==0)
			            locs[i]=-1;
			    }
			    else{
			        locs[i]++;
			        break;
			    }
			}
			if (i==-1)
			    break;
		}else{
			locs[comb_len-1]++;
		}

	}


	free(locs);
	destruct_seq(&seq);

}

void generate_sequences(){
	int i;

	for (i=0;i<sizeof(sequence_lengths)/sizeof(sequence_lengths[0]);i++){
		int len = sequence_lengths[i];
		int ins_low_count = 2;
		int ins_high_count = (int)(len/2.0)==len/2 ? len/2 : len/2-1;
		int j;

		part_generated=0;

		for (j=ins_low_count;j<=ins_high_count;j++){
			int *possible_indexes;
			int z;
			unsigned long comb_num;
			int *choices;
			int *choice;




			possible_indexes = malloc((len-1)*sizeof(int));
			for (z=1;z<len;z++){
			    possible_indexes[z-1]=z;
			}

			choices = combinations(possible_indexes,len-1,j,&comb_num);

			comb_num = *(unsigned long*)choices; //the first 8 bytes

			choice = malloc(j*sizeof(int));

			for (z=0;z<comb_num;z++){
			    int k;
			    int *adr ;
			    for (k=0,adr=&choices[2+(z*j)];k<j;k++){ //+2: the first 2 words are len
			        choice[k] = adr[k];
			    }
			    build_permutations(choice,len,j);
			}
			free(choices);

			free(possible_indexes);
			free(choice);

		} /* end of j */

		printf("\033[32m[>] \033[0m Total sequences for len %d = %lu\n",sequence_lengths[i],part_generated);
		total_generated+= part_generated;
	}
	for (i=0;i<evaluator_count;i++){
			if (eval_boards[i].running == 0){
			        kill(eval_boards[i].pid,SIGUSR1);
			        eval_boards[i].running = 1;
			}
	}

};
void test_run_seq(sequence_container *seq){
	struct eval_block e;

	copy_seq(&e,seq);

	exec_seq_linear(&e,0);
}
void *watch_evals(void *arg){
	siginfo_t sig;
	int i;
	cprint("[>] Watcher started\n");
	do{
		waitid(P_ALL,0,&sig,WSTOPPED | WEXITED);
		if (shutdown) return 0;

		for (i=0;i<evaluator_count;i++){
			if (eval_boards[i].pid == sig.si_pid){
			    int e_pid;
			    cprint("[>] Stop index: %d\n",eval_boards[i].running_seq);
			    e_pid = fork();
			    if (e_pid==-1){
			        cexit(-1,0,"fork failed");
			    }else if(e_pid){
			        //printf("[>] Respawned %d -> %d\n",eval_boards[i].pid,e_pid);

			    }else{
			    	//evaluator process

			        evaluator_start(i);
			    }
			    break;
			}
		}
	}while(1);

}
void start_evaluators(){
	int i;
	int e_pid;

	/*
		Start evaluators
		One board for each evaluator
	*/
	eval_boards = mmap(NULL, 4096 , PROT_READ | PROT_WRITE , MAP_SHARED | MAP_ANONYMOUS , -1 ,0);

	for (i=0;i<evaluator_count;i++){
		eval_boards[i].shm = mmap(NULL, BLOCKS_NUM*LINEAR_SEQ_SIZE  , PROT_READ | PROT_WRITE , MAP_SHARED | MAP_ANONYMOUS , -1 ,0);
		memset(eval_boards[i].shm,0,BLOCKS_NUM*sizeof(struct eval_block));

		e_pid=fork();
		if (e_pid==-1){
			cexit(-1,0,"fork");
		}else if(!e_pid){
			eval_boards[i].pid = getpid();
			eval_boards[i].poc_index = 0;
			evaluator_start(i);
		}
		printf("\033[32m[>] \033[0m Eval %d ready \n",e_pid);
		//eval_pids[current_evaluator++] = e_pid;

	}
	/* Start a thread to watch the evaluators */
	pthread_create(&watch_thread,NULL,&watch_evals,0);
	sleep(1);
}
void normal_exit(){
	shutdown = 1;
	printf("[>] %d Shutting down normally\n",getpid());
	//pthread_cancel(watch_thread);
	shutdown_other_evals();
	exit(0);
}
void int_handler(int sig){
	if (getpid()!=main_pid) return;
	normal_exit();
}

void sigusr_handler(int sig){
	//Shutdown signal from evaluators to main process
	normal_exit();
}
int main(int atgc, char **argv){
	int i;
	total_generated=0;

	main_pid = getpid();

	system("clear");

	printf("\033[32m[>] main:\033[0m  %d started\n",main_pid);
	printf("\033[32m[>] \033[0m START (evaluators)\n");


	/*
		Size classes initialization
	*/
	for (i=0;i<(sizeof(sz_class.allocate)/sizeof(sz_class.allocate[0]));i++){
		sz_class.allocate[i]=allocation_sizes[i];
	}
	for (i=0;i<(sizeof(sz_class.overflow)/sizeof(sz_class.overflow[0]));i++){
		sz_class.overflow[i]=overflow_sizes[i];
	}



	if (0){
		//[A:64 A:64 F:0 A:160 F:2 A:160 F:1 ]
		sequence_container seq;
		init_sequence(&seq,6,3);
		seq.data = "AFOFAA";
		int locs[3] = {0,0,0};
		build_desc(&seq,locs,3,'A');
		int n[3]={0,0,0};
		build_desc(&seq,n,3,'I');
		n[0]=0;
		build_desc(&seq,n,1,'O');
		print_exec_sequence(&seq); printf("\n");


		//eval_engine_finalize(&seq,1);
		test_run_seq(&seq);
		sleep(100);
	}


	if (access("results",F_OK))
		system("mkdir results");

	start_evaluators();
	signal(SIGINT, int_handler);
	signal(SIGUSR2, sigusr_handler);
	generate_sequences();
	sleep(2);
	printf("\n\nAll combinations generated. You can press ctrl+c to exit.\n");
	sleep(100);
	return 0;
}


/* **********************************************************************
   * UUCP-RA.C  - UUCP <==> Remote Access message processor.            *
   *                                                                    *
   * Written by Fredric L. Rice, December 1992.                         *
   * The Skeptic Tank, 1:102/890.0, FidoNet, (818) 914-9601             *
   *                                                                    *
   ********************************************************************** */

#include <alloc.h>
#include <ctype.h>
#include <conio.h>
#include <dir.h>
#include <dos.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifndef __LARGE__
    #error You must compile in Large memory model
#endif

/* **********************************************************************
   * Define various macros that will be needed.                         *
   *                                                                    *
   ********************************************************************** */

#define skipspace(s)    while (isspace(*s))  ++(s)

/* **********************************************************************
   * Define the global constants that will be used.                     *
   *                                                                    *
   ********************************************************************** */

#define TRUE            1
#define FALSE           0
#define BOOL            unsigned char
#define VERSION         "1.9"

/* **********************************************************************
   * The message file format offered here is Fido format.  The files    *
   * which use this format are the FidoNet *.MSG message files.         *
   *                                                                    *
   ********************************************************************** */

   static struct fido_msg {
      char from[36];                  /* Who the message is from             */
      char to[36];                    /* Who the message to to               */
      char subject[72];               /* The subject of the message.         */
      char date[20];                  /* Message createion date/time         */
      unsigned int times;             /* Number of time the message was read */
      unsigned int destination_node;  /* Intended destination node           */
      unsigned int originate_node;    /* The originator node of the message  */
      unsigned int cost;              /* Cost to send this message           */
      unsigned int originate_net;     /* The originator net of the message   */
      unsigned int destination_net;   /* Intended destination net number     */
      unsigned int destination_zone;  /* Intended zone for the message       */
      unsigned int originate_zone;    /* The zone of the originating system  */
      unsigned int destination_point; /* Is there a point to destination?    */
      unsigned int originate_point;   /* The point originated the message    */
      unsigned int reply;             /* Thread to previous reply            */
      unsigned int attribute;         /* Message type                        */
      unsigned int upwards_reply;     /* Thread to next message reply        */
   } message;                         /* Something to store this structure   */

/* **********************************************************************
   * 'Attribute' bit definitions, some of which we will use             *
   *                                                                    *
   ********************************************************************** */

#define Fido_Private            0x0001
#define Fido_Crash              0x0002
#define Fido_Read               0x0004
#define Fido_Sent               0x0008
#define Fido_File_Attach        0x0010
#define Fido_Forward            0x0020
#define Fido_Orphan             0x0040
#define Fido_Kill               0x0080
#define Fido_Local              0x0100
#define Fido_Hold               0x0200
#define Fido_Reserved1          0x0400
#define Fido_File_Request       0x0800
#define Fido_Ret_Rec_Req        0x1000
#define Fido_Ret_Rec            0x2000
#define Fido_Req_Audit_Trail    0x4000
#define Fido_Update_Req         0x8000

/* **********************************************************************
   * MSGINFO.BBS File structure                                         *
   *                                                                    *
   * Element 'total_on_board' is an array of words which indicates the  *
   * number of messages in each message area (board). If you wanted to  *
   * find out how many messages were on board 3, for instance, you      *
   * would access total_on_board[2].                                    *
   *                                                                    *
   ********************************************************************** */

    static struct Message_Information {
        unsigned int lowest_message;
        unsigned int highest_message;
        unsigned int total_messages;
        unsigned int total_on_board[200];
    } msg_info;

/* **********************************************************************
   * MSGIDX.BBS File structure                                          *
   *                                                                    *
   ********************************************************************** */

    static struct Message_Index {
        unsigned int message_number;
        unsigned char board_number;
    } msg_index;

/* **********************************************************************
   * MSGTOIDX.BBS File structure                                        *
   *                                                                    *
   * Since the data structure indicates a Pascal convention of storage  *
   * of the string length prior to the actual string, we allocate a     *
   * single byte called 'string_length' and use it to insert a NULL     *
   * into the element 'to_record[]' to make it conform to the C         *
   * convention of a NULL terminated string. We do this for each string *
   * element that happens to occur in the Remote Access message         *
   * subsystem.                                                         *
   *                                                                    *
   * Note: We don't use this file in this program. It's simply offered  *
   * in the event someone wants to know what the format is for it.      *
   *                                                                    *
   ********************************************************************** */

    static struct Message_To_Index {
        unsigned char string_length;    /* Length of next field         */
        char to_record[35];             /* Null padded                  */
    } msg_to;

/* **********************************************************************
   * MSGHDR.BBS File structure                                          *
   *                                                                    *
   * message_number is somewhat redundant yet offers some validation of *
   *     the Remote Access data files.                                  *
   *                                                                    *
   * start_block indicates an index into the message text file:         *
   *    MSGTXT.BBS. Each block in the text file is 255 bytes long and   *
   *    there is some additional overhead for the length of the string  *
   *    that describes the messages. To find the starting point of the  *
   *    text of this message, then, you would multiply the size of the  *
   *    message text structure by the starting block number offered     *
   *    here, and you yield a byte offset that may be used to seek into *
   *    the text file.                                                  *
   *                                                                    *
   * message_attribute is defined in the defines.                       *
   *                                                                    *
   * network_attribute is also defined with some defines.               *
   *                                                                    *
   * board is somewhat redundant also yet could be used to validate the *
   *    Remote Access data files when used with the message number and  *
   *    the message index file.                                         *
   *                                                                    *
   * date, time, who_to, who_from, subject - These are all not          *
   *    specifically NULL terminated though they may be. Reguardless,   *
   *    the bytes prior to them indicate the strings length.            *
   *                                                                    *
   ********************************************************************** */

    static struct Message_Header {
        unsigned int message_number;
        unsigned int previous_reply;
        unsigned int next_reply;
        unsigned int times_read;
        unsigned int start_block;
        unsigned int number_blocks;
        unsigned int destination_network;
        unsigned int destination_node;
        unsigned int originating_network;
        unsigned int originating_node;
        unsigned char destination_zone;
        unsigned char origination_zone;
        unsigned int cost;
        unsigned char message_attribute;
        unsigned char network_attribute;
        unsigned char board;
        unsigned char ptlength;         /* Hard-coded to 5              */
        char post_time[5];              /* hh:mm                        */
        unsigned char pdlength;         /* Hard-coded to 8              */
        char post_date[8];              /* mm-dd-yy                     */
        unsigned char wtlength;         /* Length of next field         */
        char who_to[35];                /* Null padded                  */
        unsigned char wflength;         /* Length of next field         */
        char who_from[35];              /* Null padded                  */
        unsigned char slength;          /* Length of next field         */
        char subject[72];               /* Null padded                  */
    } msg_hdr;

/* **********************************************************************
   * Message Attribute defines                                          *
   *                                                                    *
   ********************************************************************** */

#define MA_Deleted                              0x01
#define MA_Unmoved_Outbound_Net_Message         0x02
#define MA_Netmail_Message                      0x04
#define MA_Private                              0x08
#define MA_Received                             0x10
#define MA_Unmoved_Outbound_Echo_Message        0x20
#define MA_Local                                0x40
#define MA_Reserved                             0x80

/* **********************************************************************
   * Network Attribute defines                                          *
   *                                                                    *
   ********************************************************************** */

#define NA_Kill_Sent            0x01
#define NA_Sent_OK              0x02
#define NA_File_Attach          0x04
#define NA_Crash_Mail           0x08
#define NA_Request_Receipt      0x10
#define NA_Audit_Request        0x20
#define NA_Is_Return_Receipt    0x40
#define NA_Reserved             0x80

/* **********************************************************************
   * MSGTXT.BBS File structure                                          *
   *                                                                    *
   * The text of the messages is offered with the first byte indicating *
   * the length of the block that's actually used. It could be that all *
   * of the 255 byte block is used for the message and that the next    *
   * blocks will likewise also be fully used. Good going, Remote Access *
   * guys, this saves a LOT of unused disk space.                       *
   *                                                                    *
   * Remote access places the ^A Kludge lines at the top of the text    *
   * file here. There is a product ID (Kludge PID:), and a message ID,  *
   * (Kludge MSGID:). Both of these Kludge lines are terminated with a  *
   * carriage return.                                                   *
   *                                                                    *
   * The lines of the text occures next. Each line is terminated with a *
   * carriage return.                                                   *
   *                                                                    *
   * A 'tear line' comes after all of the text. This is the ---         *
   * characters which indicates that what follows is a human-readable   *
   * identification which usually offers the origination text line of   *
   * the originating system. The tear line can also be used to indicate *
   * that anything which follows may be discarded as unimportant. For   *
   * most, if not all, of the FidoNet world, information after the tear *
   * line is never discarded. This tear line is terminated with both a  *
   * carriage return _AND_ a line feed.                                 *
   *                                                                    *
   * The originating systems origin line comes next (if there is to be  *
   * an origin line. Network and local mail will probably not have an   *
   * origin line). It is terminated with a carriage return.             *
   *                                                                    *
   * The rest of the 255 byte block (if there is more) is all NULLs.    *
   *                                                                    *
   * If the person who entered the message allowed the entry to         *
   * automatically word wrap, then rather than there being a carriage   *
   * return, there will be a soft carriage return. This is, instead of  *
   * a 0x0d, a 0x8d.                                                    *
   *                                                                    *
   * Note: We don't use this file in this program. It's simply offered  *
   * in the event someone wants to know what the format is for it.      *
   *                                                                    *
   ********************************************************************** */

    static struct Message_Text {
        unsigned char trlength;         /* Length of next field         */
        unsigned char text_record[255]; /* CR delimited, NULL padded    */
    } msg_text;

/* **********************************************************************
   * The linked list of Origin Block text lines is maintained here.     *
   *                                                                    *
   ********************************************************************** */

    static struct Origin_Block {
	unsigned char *text;            /* Pointer to the message text  */
        struct Origin_Block *next;      /* Pointer to the next one.     */
    } *ob_first, *ob_last, *ob_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * We process the text file as lines in a linked list.                *
   *                                                                    *
   ********************************************************************** */

    static struct Text_File {
        char *value;                    /* Pointer to the value to send */
        struct Text_File *next;         /* Pointer to the next one      */
    } *tf_first, *tf_last, *tf_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * ErrorLevel values.                                                 *
   *                                                                    *
   ********************************************************************** */

#define No_Problem              0
#define Missing_Config          10
#define Bad_System_Address      11
#define Bad_Inbound_Folder      12
#define Bad_Gate_Address        13
#define Missing_Network         14
#define Missing_RA_Dir          15
#define Cant_Open_Message_Base  16
#define Folder_Area_Bad         17
#define Fail_Write              18
#define Cant_Read_Message       19
#define Seek_Failed		20
#define No_Nodelist_Offered     21
#define Cant_Open_Nodelist      22
#define No_Memory               23
#define Cant_Create_MSG_File    24
#define Cant_Write_MSG_File     25
#define Cant_Seek_Text_File     26
#define Cant_Read_Text_File     27
#define Cant_Seek_Header_File   28
#define Cant_Update_Header      29
#define Config_Hold_Error       30
#define Config_Immediate_Error  31
#define Cant_Open_MSG_File      32
#define Config_Kludge_Error     33
#define Config_Crash_Error      34
#define Bad_Outbound_Folder     35
#define Missing_Outbound_Folder 36
#define Config_Inform_Error     37
#define Config_Echo_Error       38
#define Config_Kill_Error       39
#define Cant_Create_List_File   40
#define Toss_To_Outbound        100
#define Toss_To_Inbound         101
#define Toss_Both_Out_In_Bound  102

/* **********************************************************************
   * Here is where the data is defined.                                 *
   *                                                                    *
   ********************************************************************** */

    static BOOL diag, testing;
    static char log_directory[201];
    static unsigned int f_zone, f_net, f_node, f_point;
    static unsigned int g_zone, g_net, g_node, g_point;
    static unsigned char network_directory[201];
    static unsigned int inbound_mail_folder;
    static BOOL log_file;
    static int highest_mail;
    static int moved_to_fidonet;
    static int moved_to_uucp;
    static unsigned char remote_access_directory[201];
    static FILE *file_log;
    static FILE *MSGINFO, *MSGIDX, *MSGTOIDX, *MSGHDR, *MSGTXT;
    static unsigned int block_count;
    static unsigned int ra_highest, ra_lowest, ra_total;
    static BOOL uucp_search;
    static BOOL uucp_all_search;
    static char nodelist_directory[201];
    static int origin_block;
    static BOOL want_hold;
    static BOOL want_keep;
    static BOOL mark_immediate;
    static BOOL mark_crash;
    static BOOL want_kludge;
    static BOOL echo_mail;
    static BOOL want_kill;
    static BOOL found_valid_to_address;
    static BOOL rewrite_message;
    static BOOL toss_only, scan_only;
    static BOOL inform_bad_address;
    
    static char *num_to_month[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    } ;

    static char *num_to_day[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    } ;

    static int outbound_folders[201];

/* **********************************************************************
   * Perform the exit ritual                                            *
   *                                                                    *
   ********************************************************************** */

static void doexit(int value)
{
    textcolor(WHITE);
    cprintf("END%c%c", 0x0d, 0x0a);
    exit(value);
}

/* **********************************************************************
   * day from 1-31, month from 1-12, year from 80                       *
   * Returns 0 for Sunday, etc.                                         *
   *                                                                    *
   *    This function was not written by Fredric Rice. It was taken     *
   *    from the MSGQ150S.LSH archive which is an on-line full          *
   *    screen editor.                                                  *
   *                                                                    *
   ********************************************************************** */

static int zeller(int day, int month, int year)
{
    int age;

    age = (year < 80) ? 20 : 19;

    if ((month -= 2) <= 0) {
        month += 12;
        year--;
    }

    return(((26 * month-2) / 10 +day +year +year / 4 + age / 4 - 2 * age) % 7);
}

/* **********************************************************************
   * Uppercase this string.                                             *
   *                                                                    *
   ********************************************************************** */

static void ucase(char *message)
{
    char byte;

    while (*message) {
        byte = *message;

        if (islower(byte)) {
            *message = _toupper(byte);
        }

        message++;
    }
}

/* **********************************************************************
   * The month is offered as text. Return it as the month number.       *
   *                                                                    *
   ********************************************************************** */

static char to_month(char *this_one)
{
    if (! strncmp(this_one, "Jan", 3)) return 1;
    if (! strncmp(this_one, "Feb", 3)) return 2;
    if (! strncmp(this_one, "Mar", 3)) return 3;
    if (! strncmp(this_one, "Apr", 3)) return 4;
    if (! strncmp(this_one, "May", 3)) return 5;
    if (! strncmp(this_one, "Jun", 3)) return 6;
    if (! strncmp(this_one, "Jul", 3)) return 7;
    if (! strncmp(this_one, "Aug", 3)) return 8;
    if (! strncmp(this_one, "Sep", 3)) return 9;
    if (! strncmp(this_one, "Oct", 3)) return 10;
    if (! strncmp(this_one, "Nov", 3)) return 11;
    if (! strncmp(this_one, "Dec", 3)) return 12;

    textcolor(LIGHTRED);

    (void)cprintf("Warning: Unable to determine what month this is: %s %c%c",
        this_one, 0x0d, 0x0a);

    return(1);
}

/* **********************************************************************
   * Find the highest message number and return it.                     *
   *                                                                    *
   ********************************************************************** */

static short find_highest_message_number(char *directory)
{
    char result;
    short highest_message_number = 0;
    char directory_search[100];
    struct ffblk file_block;

/*
 * Build the directory name to search for, include \ if needed
 */

    (void)strcpy(directory_search, directory);

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcat(directory_search, "*.MSG");

/*
 * See if we have at least one
 */

    result = findfirst(directory_search, &file_block, 0x16);

    if (! result) {
        if (atoi(file_block.ff_name) > highest_message_number) {
            highest_message_number = atoi(file_block.ff_name);
        }
    }

/*
 * Scan all messages until we know the highest message number
 */

    while (! result) {
        result = findnext(&file_block);

        if (! result) {
            if (atoi(file_block.ff_name) > highest_message_number) {
                highest_message_number = atoi(file_block.ff_name);
            }
        }
    }

/*
 * Return the value
 */

    return(highest_message_number);
}

/* **********************************************************************
   * If we have origin lines, then append them.                         *
   *                                                                    *
   ********************************************************************** */

static void append_origin_blocks(FILE *msg_out)
{
    (void)fputc(0x0d, msg_out);

    if (origin_block == 0) {
        (void)fputs("--- UUCP-RA " VERSION, msg_out);
        (void)fputc(0x0d, msg_out);
    }
    else {
        ob_point = ob_first;

        while (ob_point) {
            (void)fputs(ob_point->text, msg_out);
            (void)fputc(0x0d, msg_out);
            ob_point = ob_point->next;
        }

        (void)fputc(0x0d, msg_out);
        (void)fputs("--- UUCP-RA " VERSION, msg_out);
        (void)fputc(0x0d, msg_out);
    }
}

/* **********************************************************************
   * Seek to and read or write the selected header record.              *
   *                                                                    *
   ********************************************************************** */

static BOOL read_write_header_record(long msg_count, BOOL read_header)
{
    long seek_update;
    int result;

    seek_update = (long)msg_count * (long)sizeof(struct Message_Header);

    if (fseek(MSGHDR, (long)seek_update, SEEK_SET) != 0) {
        textcolor(LIGHTRED);
        (void)cprintf("Unable to reseek to msgheader! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Cant_Seek_Header_File);
    }

    if (read_header) {
        result = fread(&msg_hdr, sizeof(struct Message_Header), 1, MSGHDR);
        return(result == 1);
    }
    else {
        if (fwrite(&msg_hdr, sizeof(struct Message_Header), 1, MSGHDR) == 1) {
            return(TRUE);
        }

        textcolor(LIGHTRED);

        (void)cprintf("Can't update header file record message %ld! %c%c",
            msg_count, 0x0d, 0x0a);

        fcloseall();
        doexit(Cant_Update_Header);
    }

    return(TRUE);       /* Some compilers need this */
}

/* **********************************************************************
   * Make a log entry.                                                  *
   *                                                                    *
   ********************************************************************** */

static void make_log_entry(char *fname, int fsize, int where)
{
    char record[201];
    char to_string[40], from_string[40], sub_string[40];

    (void)strncpy(to_string, message.to, 15);
    (void)strncpy(from_string, message.from, 15);
    (void)strncpy(sub_string, message.subject, 25);

    (void)sprintf(record, "Domain %s To: %-15s From: %-15s Sub: %-25s\n",
	where == 0 ? " FidoNet" : " UUCP",
        to_string,
        from_string,
        sub_string);

    (void)fputs(record, file_log);

    (void)sprintf(record,
        "     Date: %s  - Size: %d -> %s\n\n", message.date, fsize, fname);

    (void)fputs(record, file_log);
}

/* **********************************************************************
   * Plug all kludge lines.                                             *
   *                                                                    *
   ********************************************************************** */

static void include_kludge(FILE *fout, int highest_move)
{
    char record[201];
    time_t the_time;

/*
 * The MSGID contains a unique number so that duplications can be
 * searched for. We use the highest message number in the move
 * directory and the current date and time. That should be fine.
 */

    the_time = time(NULL);

    (void)sprintf(record, "%cMSGID: %d:%d/%d.%d %08lx%c%c",
        0x01,
        message.originate_zone,
        message.originate_net,
        message.originate_node,
        message.originate_point,
        (unsigned long)the_time * (highest_move + 1),
        0x0d, 0x0a);

    (void)fputs(record, fout);

/*
 * See if it should be kludged as immediate and direct.
 */

    if (mark_immediate) {
        (void)sprintf(record, "%cFLAGS IMM, DIR%c%c", 0x01, 0x0d, 0x0a);
        (void)fputs(record, fout);
    }

/*
 * Add the 'topt' and 'fmpt' kludges if needed
 */

    if (f_point != 0) {

        (void)sprintf(record, "%cFMPT %d%c%c",
            0x01, message.originate_point, 0x0d, 0x0a);

        (void)fputs(record, fout);
    }

    if (message.destination_point != 0) {

        (void)sprintf(record, "%cTOPT %d%c%c",
	    0x01, message.destination_point, 0x0d, 0x0a);

        (void)fputs(record, fout);
    }

/*
 * Always add the 'INTL' kludge
 */

    (void)sprintf(record, "%cINTL %d:%d/%d.%d %d:%d/%d.%d%c%c",
        0x01,
        message.destination_zone,
        message.destination_net,
        message.destination_node,
        message.destination_point,
        f_zone,
        f_net,
        f_node,
        f_point,
        0x0d, 0x0a);

    (void)fputs(record, fout);
}

/* **********************************************************************
   * If we have ESC at the key board, stop.                             *
   *                                                                    *
   ********************************************************************** */

static BOOL keyboard_interrupt(void)
{
    if (kbhit() == 0)
        return(FALSE);

    return(getch() == 27);
}

/* **********************************************************************
   * Update the who-to index.                                           *
   *                                                                    *
   ********************************************************************** */

static void update_who_to_index(long msg_count, char *who_to)
{
    long seek_update;

    seek_update = (long)msg_count * (long)sizeof(struct Message_To_Index);

    if (fseek(MSGTOIDX, (long)seek_update, SEEK_SET) != 0) {
        textcolor(LIGHTRED);

        (void)cprintf("Unable to reseek to msgtoidx! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Cant_Seek_Header_File);
    }

    (void)strcpy(msg_to.to_record, who_to);
    msg_to.string_length = strlen(who_to);
    (void)fwrite(&msg_to, sizeof(struct Message_To_Index), 1, MSGTOIDX);
}

/* **********************************************************************
   * Append the linked list with the message text.                      *
   *                                                                    *
   ********************************************************************** */

static void plug_message_text(char *first_point)
{
    char *testing, *atpoint, *more_testing;
    char record[401], new_address[401];
    struct Text_File *tf_hold;

/*
 * Make a copy we can work with
 */

    (void)strcpy(record, first_point);
    atpoint = record;

    atpoint[strlen(atpoint) - 1] = (char)NULL;

    tf_point = (struct Text_File *)farmalloc(sizeof(struct Text_File));

    if (tf_point == (struct Text_File *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I ran out of memory! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(No_Memory);
    }

    tf_point->value = (char *)farmalloc(strlen(atpoint) + 1);

    if (tf_point->value == (char *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I ran out of memory! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(No_Memory);
    }                          

    (void)strcpy(tf_point->value, atpoint);

/*
 * See if it's the to: kludge. If it is, we want it at the top.
 * Not only that, we make sure it's a To: with a space after the :
 */

    testing = atpoint;
    skipspace(testing);

    if (! strnicmp(testing, "to:", 3)) {
        more_testing = testing;
        more_testing += 3;
        skipspace(more_testing);

        found_valid_to_address = TRUE;

        if (strncmp(atpoint, "To: ", 4)) {      /* Yes: atpoint */
            rewrite_message = TRUE;

            testing += 3;
            skipspace(testing);

            (void)farfree(tf_point->value);

            (void)strcpy(new_address, "To: ");
            (void)strcat(new_address, testing);

            tf_point->value = (char *)farmalloc(strlen(new_address) + 1);

            if (tf_point->value == (char *)NULL) {
                textcolor(LIGHTRED);

                (void)cprintf("I ran out of memory! %c%c", 0x0d, 0x0a);
                fcloseall();
                doexit(No_Memory);
            }

            (void)strcpy(tf_point->value, new_address);
        }

        if (tf_first != (struct Text_File *)NULL) {
            rewrite_message = TRUE;
            tf_hold = tf_first;
            tf_first = tf_point;
            tf_point->next = tf_hold;
            return;
        }
    }

/*
 * Append the entry in the linked list.
 */

    tf_point->next = (struct Text_File *)NULL;

    if (tf_first == (struct Text_File *)NULL) {
        tf_first = tf_point;
    }
    else {
        tf_last->next = tf_point;
    }

    tf_last = tf_point;
}

/* **********************************************************************
   * We're through with the message text. Toss it.                      *
   *                                                                    *
   ********************************************************************** */

static void toss_text_linked_list(void)
{
    struct Text_File *next;

    tf_point = tf_first;

    while (tf_point) {
        next = tf_point->next;
        farfree(tf_point->value);
        farfree(tf_point);
        tf_point = next;
    }

    tf_first = tf_last = tf_point = (struct Text_File *)NULL;
}

/* **********************************************************************
   * See if there is a to: kludge. If not, mark it as 'hold' and then   *
   * return FALSE, else return TRUE.                                    *
   *                                                                    *
   ********************************************************************** */
                                                                            
static BOOL scan_fidonet_message_for_address(char *file_name)
{
    FILE *msg_file;
    char record[401];
    unsigned int ccount;
    unsigned char byte;

/*
 * Open the file.
 */

    if ((msg_file = fopen(file_name, "r+b")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to reopen newly created message file! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Cant_Open_MSG_File);
    }

/*
 * Get the header
 */

     if (fread(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
        (void)fclose(msg_file);
        textcolor(LIGHTRED);

        (void)cprintf("Warning: can't read file: %s! %c%c",
            file_name, 0x0d, 0x0a);

        return(TRUE);
    }

    found_valid_to_address = FALSE;
    rewrite_message = FALSE;

/*
 * Scan through the message and build the linked list of all of the
 * message text.
 */

    ccount = 0;

    while (! feof(msg_file)) {
        byte = fgetc(msg_file);

        record[ccount++] = byte;
        record[ccount] = (char)NULL;

        if (byte == 0x0d || ccount >= 400) {
            plug_message_text(record);
            ccount = 0;
        }
    }

/*
 * If a to: is found, check to see if changes were made and
 * if they were, write those changes back out.
 */

    if (found_valid_to_address) {
        if (rewrite_message) {

            if (diag) {
                (void)printf("DIAG: rewrite text: %s\n", file_name);
            }

            (void)rewind(msg_file);

            if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
                textcolor(LIGHTRED);

                (void)cprintf("I was unable to rewrite message file! %c%c",
                    0x0d, 0x0a);

                fcloseall();
                doexit(Cant_Write_MSG_File);
            }

            tf_point = tf_first;

            while (tf_point) {
                (void)fputs(tf_point->value, msg_file);
                (void)fputc(0x0d, msg_file);
                tf_point = tf_point->next;
            }
        }

        toss_text_linked_list();
        (void)fclose(msg_file);
        return(TRUE);
    }

/*
 * Rewind the file, put it on hold, mark it as sent, return FALSE.
 */

    toss_text_linked_list();
    (void)rewind(msg_file);

    message.attribute |= Fido_Hold;
    message.attribute |= Fido_Sent;

    if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to write message file! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Cant_Write_MSG_File);
    }

    (void)fclose(msg_file);
    return(FALSE);
}

/* **********************************************************************
   * Process the outbound messages.                                     *
   *                                                                    *
   * We build a *.MSG file and copy all of th header information over.  *
   * The new message gets its kludge lines added and then the message   *
   * text from the original RA/QBBS text gets copied over while         *
   * excluding all kludge lines.                                        *
   *                                                                    *
   ********************************************************************** */

static void process_outbound(void)
{
    int block_count, loop;
    FILE *msg_out;
    char file_name[80];
    long text_seek, msg_count, seek_update;
    char hold[50];
    int the_day, the_month, the_year;
    BOOL do_process;
    int attribute;
    BOOL toss_kludge;

    msg_count = 0L;

    while (! feof(MSGHDR)) {
        if (keyboard_interrupt()) {
            fcloseall();
            doexit(No_Problem);
        }

        if (read_write_header_record(msg_count, TRUE)) {

            toss_kludge = FALSE;

            attribute = msg_hdr.message_attribute;

            do_process = ((attribute & MA_Unmoved_Outbound_Echo_Message) != 0);

            if (do_process)
                do_process = outbound_folders[msg_hdr.board];

            if (do_process)
                do_process = (! strnicmp(msg_hdr.who_to, "uucp", 4));

            if (do_process) {

/*
 * Make sure that we incriment the high message number so that the
 * newly created message will not overwrite an existing message.
 * Then create a message file name out of the number.
 */

                (void)sprintf(file_name, "%s%d.MSG",
                    network_directory, ++highest_mail);

                if (diag) {
                    (void)printf("DIAG: Created: %s\n", file_name);
                }

                (void)strncpy(message.from, msg_hdr.who_from, msg_hdr.wflength);
                message.from[msg_hdr.wflength] = (char)NULL;

                (void)strcpy(message.to, "uucp");

                (void)strncpy(message.subject, msg_hdr.subject, msg_hdr.slength);
                message.subject[msg_hdr.slength] = (char)NULL;

/*
 * Convert the date and time strings.
 */

                hold[0] = msg_hdr.post_date[3];
                hold[1] = msg_hdr.post_date[4];
                hold[2] = (char)NULL;
                the_day = atoi(hold);

                hold[0] = msg_hdr.post_date[0];
                hold[1] = msg_hdr.post_date[1];
                the_month = atoi(hold);

                hold[0] = msg_hdr.post_date[6];
                hold[1] = msg_hdr.post_date[7];
                the_year = atoi(hold);

                (void)sprintf(message.date, "%s %02d %s %02d %c%c%c%c%c",
                    num_to_day[zeller(the_day, the_month, the_year)],
                    the_day,
                    num_to_month[the_month - 1],
                    the_year,
                    msg_hdr.post_time[0],
                    msg_hdr.post_time[1],
                    msg_hdr.post_time[2],
                    msg_hdr.post_time[3],
                    msg_hdr.post_time[4]);

                message.times = 0;
                message.cost = 0;
                message.reply = 0;

/*
 * Make the attribute
 */

                message.attribute = Fido_Local;

                if (want_kill)
                    message.attribute += Fido_Kill;

                if (want_hold)
                    message.attribute += Fido_Hold;

                if (mark_crash)
                    message.attribute += Fido_Crash;

                message.upwards_reply = 0;

                message.originate_zone = f_zone;
                message.originate_net = f_net;
                message.originate_node = f_node;
                message.originate_point = f_point;

                message.destination_zone = g_zone;
                message.destination_net = g_net;
                message.destination_node = g_node;
                message.destination_point = g_point;

/*
 * Make sure that we can create the new message now and
 * write the message header into the file.
 */

                if ((msg_out = fopen(file_name, "wb")) == (FILE *)NULL) {
                    textcolor(LIGHTRED);

                    (void)cprintf("I was unable to create message file! %c%c",
                        0x0d, 0x0a);

                    fcloseall();
                    doexit(Cant_Create_MSG_File);
                }

                if (fwrite(&message, sizeof(struct fido_msg), 1, msg_out) != 1) {
                    textcolor(LIGHTRED);

                    (void)cprintf("I was unable to write message file! %c%c",
                        0x0d, 0x0a);

                    fcloseall();
                    doexit(Cant_Write_MSG_File);
                }

                if (log_file)
                    make_log_entry(file_name, msg_hdr.number_blocks * 255, 1);

                if (want_kludge)
                    include_kludge(msg_out, highest_mail);

/*
 * Copy the message text into the msg file. No evaluation
 * is performed and nothing is extracted.
 */

                text_seek =
                    (long)((long)(msg_hdr.start_block) *
                    (long)sizeof(struct Message_Text));

                if (fseek(MSGTXT, (long)text_seek, SEEK_SET) > 0) {
                    textcolor(LIGHTRED);

                    (void)cprintf("Unable to seek to: %ld! %c%c",
                        text_seek, 0x0d, 0x0a);

                    fcloseall();
                    doexit(Cant_Seek_Text_File);
                }

                for (block_count = 0;
                    block_count < msg_hdr.number_blocks;
                        block_count++) {

		    if (fread(&msg_text, sizeof(struct Message_Text), 1, MSGTXT) == 1) {
                        for (loop = 0; loop < msg_text.trlength; loop++) {
                            if (! toss_kludge) {
                                if (msg_text.text_record[loop] == 0x01) {
                                    toss_kludge = TRUE;
                                }
                                else {
                                    (void)fputc(msg_text.text_record[loop],
                                        msg_out);
                                }
                            }
                            else {
                                if (msg_text.text_record[loop] == 0x0d) {
                                    toss_kludge = FALSE;
                                }
                            }
                        }
                    }
                    else {
                        textcolor(LIGHTRED);

                        (void)cprintf("Copy of message incompleate! %c%c",
                            0x0d, 0x0a);

                        fcloseall();
                        return;
                    }
                }

/*
 * Tossed without a problem. Append Origin Block text if needed, and
 * then close the output file and then mark the header file element
 * to indicate that it's been moved.
 */

                append_origin_blocks(msg_out);
                (void)fclose(msg_out);
                moved_to_fidonet++;

/*
 * If there was no to: kludge in the message text then we
 * have a bit of a problem. Readdress the message back to
 * the originator in the Remote Access folder if the
 * configuration says that we may.
 *
 * We only mark mail as 'moved' if it has a valid To: address.
 */

                if (! scan_fidonet_message_for_address(file_name)) {
                    if (diag) {
                        (void)printf("DIAG: No to: address found\n");
                    }

                    if (inform_bad_address) {
                        if (diag) {
                            (void)printf("DIAG: Message readdressed\n");
                        }

                        (void)strcpy(msg_hdr.who_to, msg_hdr.who_from);
                        msg_hdr.wtlength = strlen(msg_hdr.who_to);

                        (void)strcpy(msg_hdr.who_from, "UUCP-RA");
                        msg_hdr.wflength = strlen(msg_hdr.who_from);

                        (void)strcpy(msg_hdr.subject, "TO: ADDRESS MISSING!");
                        msg_hdr.slength = strlen(msg_hdr.subject);

                        update_who_to_index(msg_count, msg_hdr.who_to);
                    }
                    else {
                        if (diag) {
                            (void)printf(
                                "DIAG: Message %s not readdressed; killed\n",
                                file_name);
                        }

                        moved_to_fidonet--;
                        highest_mail--;
                        (void)unlink(file_name);
                    }
                }
                else {
                    if (diag) {
                        (void)printf("DIAG: Message moved\n");
                    }

                    attribute &= ~MA_Unmoved_Outbound_Echo_Message;
                }

                msg_hdr.message_attribute = attribute;
                (void)read_write_header_record(msg_count, FALSE);

/*
 * The write was ok. Now, when we leave here, we will read the
 * next message header information. But before we do, we must
 * seek to the very spot we are currently located so that the
 * read will be performed. Norton Guides says it's needed and
 * testing shows that the seek between reads and writes are needed.
 */

                seek_update = (long)ftell(MSGHDR);
                (void)fseek(MSGHDR, (long)seek_update, SEEK_SET);
            }

            msg_count++;
        }
        else {
            return;
        }
    }
}

/* **********************************************************************
   * o Modify the FidoNet message.                                      *
   *                                                                    *
   * o Append information to the Remote Access message data base.       *
   *                                                                    *
   ********************************************************************** */

static void toss_message_to_ra(FILE *msg_file)
{
    unsigned int result;
    unsigned char char_count;
    unsigned char byte;
    char *point;
    char fido_time[20], fido_date[20];
    unsigned int message_block_count;

/*
 * Update the Remote Access File MSGINFO.BBS
 */

    msg_info.highest_message++;
    msg_info.total_messages++;

    if ((inbound_mail_folder - 1) > 200) {
        textcolor(LIGHTRED);

        (void)cprintf("SYSTEM EXCEPTION at point 1 occured! %c%c", 0x0d, 0x0a);
        doexit(Folder_Area_Bad);
    }

    msg_info.total_on_board[inbound_mail_folder - 1]++;
    rewind(MSGINFO);

    result =
        fwrite(&msg_info, sizeof(struct Message_Information), 1, MSGINFO);

    if (result != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to write file: MSGINFO.BBS! %c%c",
            0x0d, 0x0a);

        (void)fcloseall();
        doexit(Fail_Write);
    }

/*
 * Append to the Remote Access file MSGIDX
 */

    msg_index.message_number = msg_info.highest_message;
    msg_index.board_number = inbound_mail_folder;
    
    result =
        fwrite(&msg_index, sizeof(struct Message_Index), 1, MSGIDX);

    if (result != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to write file: MSGIDX.BBS! %c%c",
            0x0d, 0x0a);

        (void)fcloseall();
        doexit(Fail_Write);
    }

/*
 * Append to the Remote Access file MSGTOIDX
 */

    msg_to.string_length = (unsigned char)strlen(message.to);
    (void)strncpy(msg_to.to_record, message.to, 35);

    result =
        fwrite(&msg_to, sizeof(struct Message_To_Index), 1, MSGTOIDX);

    if (result != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to write file: MSGTOIDX.BBS! %c%c",
            0x0d, 0x0a);

        (void)fcloseall();
        doexit(Fail_Write);
    }

/*
 * Append to the Remote Access file MSGTXT.
 *
 * Here we compute the number of 255 byte blocks in the message
 * and the information is retained to append information to the
 * header file.
 */

    char_count = 0;
    message_block_count = 0;

    while (! feof(msg_file)) {
        byte = (unsigned char)fgetc(msg_file);

        if (! feof(msg_file)) {
            msg_text.text_record[char_count] = byte;

            if (char_count == 254) {
                msg_text.trlength = 255;
                char_count = 0;

                result =
                    fwrite(&msg_text, sizeof(struct Message_Text), 1, MSGTXT);

                if (result != 1) {
                    textcolor(LIGHTRED);

                    (void)cprintf("I was unable to write file: MSGTXT.BBS! %c%c",
                        0x0d, 0x0a);

                    (void)fcloseall();
                    doexit(Fail_Write);
                }

                message_block_count++;
            }
            else {
                char_count++;
            }
        }
    }

/*
 * Find out what the length of the last message block is and store it
 * away. Then append the remaining text field with NULLs.
 *
 * If the character count is 0, then it could be an empty message or
 * it could have ended exactly on the 255'th byte boundry.
 */

    if (char_count != 0) {
        msg_text.trlength = char_count + 1;

        for (; char_count < 255; char_count++)
            msg_text.text_record[char_count] = 0x00;

        result =
            fwrite(&msg_text, sizeof(struct Message_Text), 1, MSGTXT);

        if (result != 1) {
            textcolor(LIGHTRED);

            (void)cprintf("I was unable to write file: MSGTXT.BBS! %c%c",
                0x0d, 0x0a);

            (void)fcloseall();
            doexit(Fail_Write);
        }

        message_block_count++;
    }

/*
 * Append to the Remote Access file MSGHDR
 */

    point = message.date;
    point += 11;
    (void)strncpy(fido_time, point, 5);

    point = message.date;

    (void)sprintf(fido_date, "%02d-%02d-%02d",
        to_month(point + 3), atoi(point), atoi(point + 7));

    msg_hdr.message_number = msg_info.highest_message;
    msg_hdr.previous_reply = message.reply;
    msg_hdr.next_reply = message.upwards_reply;
    msg_hdr.times_read = 0;
    msg_hdr.start_block = block_count;
    msg_hdr.number_blocks = message_block_count;
    msg_hdr.destination_network = (unsigned int)message.destination_net;
    msg_hdr.destination_node = (unsigned int)message.destination_node;
    msg_hdr.originating_network = (unsigned int)message.originate_net;
    msg_hdr.originating_node = (unsigned int)message.originate_node;
    msg_hdr.destination_zone = (unsigned char)message.destination_zone;
    msg_hdr.origination_zone = (unsigned char)message.originate_zone;
    msg_hdr.cost = 0;

/*
 * Rework the differences in the bit patterns for the
 * message attribute and the network attribute. Take some
 * care here to make sure that they are correct!
 * message.attribute;
 */

    msg_hdr.message_attribute = (unsigned char)0;
    msg_hdr.network_attribute = (unsigned char)0;

    if ((message.attribute & Fido_Private) > 0)
        msg_hdr.message_attribute += MA_Private;

    if ((message.attribute & Fido_Crash) > 0)
        msg_hdr.network_attribute += NA_Crash_Mail;

    if ((message.attribute & Fido_Read) > 0)
        msg_hdr.message_attribute += MA_Received;

    if ((message.attribute & Fido_Sent) > 0)
        msg_hdr.network_attribute += NA_Sent_OK;

    if ((message.attribute & Fido_File_Attach) > 0)
        msg_hdr.network_attribute += NA_File_Attach;

/* Fido_Forward   Fido_Orphan */

    if ((message.attribute & Fido_Kill) > 0)
        msg_hdr.network_attribute += NA_Kill_Sent;

/* Fido_Local   Fido_Hold   Fido_Reserved1   Fido_Req */

    if ((message.attribute & Fido_Ret_Rec_Req) > 0)
        msg_hdr.network_attribute += NA_Request_Receipt;

    if ((message.attribute & Fido_Ret_Rec) > 0)
        msg_hdr.network_attribute += NA_Is_Return_Receipt;

    if ((message.attribute & Fido_Req_Audit_Trail) > 0)
        msg_hdr.network_attribute += NA_Audit_Request;

/* Fido_Update_Req */

/*
 * We leave the following bits cleared because they're being moved
 * from *.MSG format over to the RA/QBBS format
 *
 * MA_Deleted
 * MA_Unmoved_Outbound_Net_Message
 * MA_Netmail_Message
 * MA_Unmoved_Outbound_Echo_Message
 * MA_Reserved
 * NA_Reserved
 */

    msg_hdr.board = inbound_mail_folder;
    msg_hdr.ptlength = 5;
    (void)strncpy(msg_hdr.post_time, fido_time, 5);
    msg_hdr.pdlength = 8;
    (void)strncpy(msg_hdr.post_date, fido_date, 8);
    msg_hdr.wtlength = (unsigned char)strlen(message.to);
    (void)strncpy(msg_hdr.who_to, message.to, 35);
    msg_hdr.wflength = (unsigned char)strlen(message.from);
    (void)strncpy(msg_hdr.who_from, message.from, 35);
    msg_hdr.slength = (unsigned char)strlen(message.subject);
    (void)strncpy(msg_hdr.subject, message.subject, 72);

    result =
        fwrite(&msg_hdr, sizeof(struct Message_Header), 1, MSGHDR);

    if (result != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to write file: MSGHDR.BBS! %c%c",
            0x0d, 0x0a);

        (void)fcloseall();
        doexit(Fail_Write);
    }

/*
 * Make sure that we keep track of the block count!
*/

    block_count += msg_hdr.number_blocks;
}

/* **********************************************************************
   * Initialize everything.                                             *
   *                                                                    *
   ********************************************************************** */

static void initialize_module(void)
{
    int loop;

    diag = testing = FALSE;
    f_zone = f_net = f_node = f_point = 0;
    g_zone = g_net = g_node = g_point = 0;
    network_directory[0] = (char)NULL;
    inbound_mail_folder = 0;
    log_file = FALSE;
    highest_mail = 0;
    moved_to_fidonet = 0;
    moved_to_uucp = 0;
    remote_access_directory[0] = (char)NULL;
    file_log = (FILE *)NULL;
    block_count = 0;
    ra_highest= ra_lowest = ra_total = 0;
    uucp_search = FALSE;
    uucp_all_search = FALSE;
    nodelist_directory[0] = (char)NULL;
    ob_first = ob_last = ob_point = (struct Origin_Block *)NULL;
    origin_block = 0;
    MSGINFO = MSGIDX = MSGTOIDX = MSGHDR = MSGTXT = (FILE *)NULL;
    want_hold = FALSE;
    want_keep = FALSE;
    mark_immediate = FALSE;
    mark_crash = FALSE;
    want_kludge = TRUE;
    echo_mail = FALSE;
    want_kill = TRUE;
    inform_bad_address = FALSE;
    tf_first = tf_last = tf_point = (struct Text_File *)NULL;
    rewrite_message = FALSE;
    toss_only = scan_only = FALSE;

    for (loop = 0; loop < 200; loop++)
        outbound_folders[loop] = FALSE;
}

/* **********************************************************************
   * We know where the Remote Access files are kept, now make sure      *
   * that they can be opened! Do so now, taking care with the mode      *
   * that's used. Some should be appended while others need to be       *
   * read at their start point.                                         *
   *                                                                    *
   * 'appendant'                                                        *
   *    If we are scanning the *.MSG messages and putting any messages  *
   *    we find into the Remote Access system, then we typically will   *
   *    be appending information to files. If this is the case, we will *
   *    open then for append.                                           *
   *                                                                    *
   *    If we are scanning the Remote Access data base, we will want to *
   *    open the files for read and update.                             *
   *                                                                    *
   ********************************************************************** */

static void get_ra_information(BOOL appendant)
{
    char record[201];
    unsigned long hold_bc;
    unsigned int result;

    (void)sprintf(record, "%smsginfo.bbs", remote_access_directory);

    if ((MSGINFO = fopen(record, "r+b")) == (FILE *)NULL) {     /* W and R */
        textcolor(LIGHTRED);

        (void)cprintf("File: %s could not be opened! %c%c",
            record, 0x0d, 0x0a);

        doexit(Cant_Open_Message_Base);
    }

    if (diag) {
        (void)printf("DIAG: File %s opened for update\n", record);
    }

    (void)sprintf(record, "%smsgidx.bbs", remote_access_directory);

    if ((MSGIDX = fopen(record, appendant ? "a+b" : "r+b")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("File: %s could not be opened! %c%c",
            record, 0x0d, 0x0a);

        doexit(Cant_Open_Message_Base);
    }

    if (diag) {
        (void)printf("DIAG: File %s opened for %s\n",
            record, appendant ? "apppend" : "update");
    }

    (void)sprintf(record, "%smsgtoidx.bbs", remote_access_directory);

    if ((MSGTOIDX = fopen(record, appendant ? "a+b" : "r+b")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("File: %s could not be opened! %c%c",
            record, 0x0d, 0x0a);

        doexit(Cant_Open_Message_Base);
    }

    if (diag) {
        (void)printf("DIAG: File %s opened for %s\n",
            record, appendant ? "apppend" : "update");
    }

    (void)sprintf(record, "%smsghdr.bbs", remote_access_directory);

    if ((MSGHDR = fopen(record, appendant ? "a+b" : "r+b")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("File: %s could not be opened! %c%c",
            record, 0x0d, 0x0a);

        doexit(Cant_Open_Message_Base);
    }

    if (diag) {
        (void)printf("DIAG: File %s opened for %s\n",
            record, appendant ? "apppend" : "update");
    }

    (void)sprintf(record, "%smsgtxt.bbs", remote_access_directory);

    if ((MSGTXT = fopen(record, appendant ? "a+b" : "r+b")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("File: %s could not be opened! %c%c",
            record, 0x0d, 0x0a);

        doexit(Cant_Open_Message_Base);
    }

    if (diag) {
        (void)printf("DIAG: File %s opened for %s\n",
            record, appendant ? "apppend" : "update");
    }

/*
 * Count the number of blocks in the text file and then
 * keep it at its end to get ready for appending.
 */

    hold_bc = (unsigned long)filelength(fileno(MSGTXT)) / 256L;
    block_count = (unsigned short)hold_bc;

/*
 * How many messages are in the Remote Access message system?
 * This information is for display only. When the information
 * is updated in the file, the structure elements are updated.
 */

    result =
        fread(&msg_info, sizeof(struct Message_Information), 1, MSGINFO);

    if (result != 1) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to read file: MSGINFO.BBS! %c%c",
            0x0d, 0x0a);

        (void)fcloseall();
        doexit(Cant_Read_Message);
    }

    ra_lowest = msg_info.lowest_message;
    ra_highest = msg_info.highest_message;
    ra_total = msg_info.total_messages;

    if (diag) {
        (void)printf(
            "DIAG: Blk Cnt: %d RA_lowest: %d, RA_highest: %d, RA_total: %d\n",
            block_count, ra_lowest, ra_highest, ra_total);
    }
}

/* **********************************************************************
   * Extract the network address from the string offered and stuff      *
   * everything into the addresses memory bytes offered.                *
   *                                                                    *
   ********************************************************************** */

static void plug_address(char *atpoint,
    unsigned int *zone,
    unsigned int *net,
    unsigned int *node,
    unsigned int *point)
{
/*
 * Extract systems zone
 */

    *zone = atoi(atpoint);

/*
 * Toss digits which comprise the zone
 */

    while (*atpoint >= '0' && *atpoint <= '9')
        atpoint++;

/*
 * Make sure the next character is a :. If it's not (like an end of
 * string or a carriage return) thenwe've not got a full address.
 */

    if (*atpoint != ':' || *zone < 1) {
        textcolor(LIGHTRED);

        (void)cprintf("SYSTEM command has unusual network address! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_System_Address);
    }

    if (diag) {
        (void)printf("DIAG: Network address zone %d\n", *zone);
    }

/*
 * Skip past the :
 */

    atpoint++;

/*
 * Extract the network
 */

    *net = atoi(atpoint);

/*
 * Skip past the network digits
 */

    while (*atpoint >= '0' && *atpoint <= '9')
        atpoint++;

/*
 * See if the next character is a /
 */

    if (*atpoint != '/' || *net < 1) {
        textcolor(LIGHTRED);

        (void)cprintf("SYSTEM command has unusual network address! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_System_Address);
    }

    if (diag) {
        (void)printf("DIAG: Network address net %d\n", *net);
    }

/*
 * Skip past the /
 */

    atpoint++;

/*
 * Extract the node number
 */

    *node = atoi(atpoint);

/*
 * Skip past the node number
 */

    while (*atpoint >= '0' && *atpoint <= '9')
        atpoint++;

/*
 * If the next character is not a . then the address is strange.
 */

    if (*atpoint != '.' || *node < 0) {
        textcolor(LIGHTRED);

        (void)cprintf("SYSTEM command has unusual network address! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_System_Address);
    }

    if (diag) {
        (void)printf("DIAG: Network address node %d\n", *node);
    }

/*
 * Skip past the .
 */

    atpoint++;

/*
 * Extract the point number.
 */

    *point = atoi(atpoint);

    if (diag) {
        (void)printf("DIAG: Network address point %d\n", *point);
    }
}

/* **********************************************************************
   * See if the log file should be on or off.                           *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_log_file(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: log with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        log_file = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        log_file = FALSE;
    }
    else {
        textcolor(YELLOW);

        (void)cprintf("WARNING: Config file error: LOG command parameter! %c%c",
            0x0d, 0x0a);

        log_file = FALSE;
    }                                       
}

/* **********************************************************************
   * Store the network mail directory, appending \ to the end if it     *
   * is needed.                                                         *
   *                                                                    *
   ********************************************************************** */

static void plug_network_directory(char *atpoint)
{
    char directory[201];

    if (diag) {
        (void)printf("DIAG: network with %s\n", atpoint);
    }

    (void)strcpy(directory, atpoint);
    directory[strlen(directory) - 1] = (char)NULL;

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcpy(network_directory, directory);
}

/* **********************************************************************
   * Store the nodelist directory.                                      *
   *                                                                    *
   ********************************************************************** */

static void plug_nodelist_directory(char *atpoint)
{
    char directory[201];

    if (diag) {
        (void)printf("DIAG: nodelist with %s\n", atpoint);
    }

    (void)strcpy(directory, atpoint);
    directory[strlen(directory) - 1] = (char)NULL;
    (void)strcpy(nodelist_directory, directory);
}

/* **********************************************************************
   * Store the inbound folder number.                                   *
   *                                                                    *
   ********************************************************************** */

static void plug_inbound_folder(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: inbound folder with %s\n", atpoint);
    }

    inbound_mail_folder = atoi(atpoint);

    if (inbound_mail_folder < 1 || inbound_mail_folder > 200) {
        textcolor(LIGHTRED);

        (void)cprintf("Inbound Folder number in configuration is invalid! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_Inbound_Folder);
    }
}

/* **********************************************************************
   * Store an outbound folder number.                                   *
   *                                                                    *
   ********************************************************************** */

static void plug_outbound_folder(char *atpoint)
{
    int outbound_mail_folder;

    if (diag) {
        (void)printf("DIAG: outbound folder with %s\n", atpoint);
    }

    outbound_mail_folder = atoi(atpoint);

    if (outbound_mail_folder < 1 || outbound_mail_folder > 200) {
        textcolor(LIGHTRED);

        (void)cprintf("Outbound Folder number in configuration is invalid! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_Outbound_Folder);
    }

    outbound_folders[outbound_mail_folder] = TRUE;
}

/* **********************************************************************
   * Plug the remote access directory.                                  *
   *                                                                    *
   ********************************************************************** */

static void plug_ra_directory(char *atpoint)
{
    char directory[201];

    if (diag) {
        (void)printf("DIAG: radir with %s\n", atpoint);
    }

    (void)strcpy(directory, atpoint);
    directory[strlen(directory) - 1] = (char)NULL;

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcpy(remote_access_directory, directory);
}

/* **********************************************************************
   * Append an entry in the origin line block.                          *
   *                                                                    *
   ********************************************************************** */

static void plug_origin_line(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;  /* Strip cr from end */

/*
 * Allocate memory for the data structure of the linked list
 */

    ob_point = (struct Origin_Block *)farmalloc(sizeof(struct Origin_Block));

    if (ob_point == (struct Origin_Block *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I ran out of memory! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(No_Memory);
    }

/*
 * Allocate memory for the origin line text
 */

    ob_point->text = (char *)farmalloc(strlen(atpoint) + 2);

    if (ob_point->text == (char *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I ran out of memory! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(No_Memory);
    }

/*
 * Copy it over
 */

    (void)strcpy(ob_point->text, atpoint);

    if (diag) {
        (void)printf("DIAG: origin %s\n", ob_point->text);
    }

/*
 * Append the entry in the linked list.
 */

    ob_point->next = (struct Origin_Block *)NULL;

    if (ob_first == (struct Origin_Block *)NULL) {
        ob_first = ob_point;
    }
    else {
        ob_last->next = ob_point;
    }

    ob_last = ob_point;
    origin_block++;
}

/* **********************************************************************
   * We have a HOLD command.                                            *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_hold(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: hold with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        want_hold = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_hold = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: HOLD command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Hold_Error);
    }
}

/* **********************************************************************
   * We have a KEEP command.                                            *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_keep(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: keep with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        want_keep = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_keep = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: KEEP command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Hold_Error);
    }
}

/* **********************************************************************
   * We have an IMMEDIATE command.                                      *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_immediate(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: immediate with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        mark_immediate = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        mark_immediate = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: IMMEDIATE command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Immediate_Error);
    } 
}

/* **********************************************************************
   * We have a CRASH command.                                           *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_crash(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: crash with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        mark_crash = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        mark_crash = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: CRASH command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Crash_Error);
    } 
}

/* **********************************************************************
   * We have a KLUDGE command.                                          *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_kludge(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: kludge with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        want_kludge = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_kludge = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: KLUDGE command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Kludge_Error);
    } 
}

/* **********************************************************************
   * We have a INFORMBAD command.                                       *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_inform_bad(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: INFORMBAD with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        inform_bad_address = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        inform_bad_address = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: INFORMBAD command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Inform_Error);
    } 
}

/* **********************************************************************
   * We have an ECHO command.                                           *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_echo(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: ECHO with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        echo_mail = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        echo_mail = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: ECHO command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Echo_Error);
    }                   
}

/* **********************************************************************
   * We have a KILL command.                                            *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */


static void plug_kill(char *atpoint)
{
    if (diag) {
        (void)printf("DIAG: KILL with %s\n", atpoint);
    }

    if (! strnicmp(atpoint, "yes", 3)) {
        want_kill = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_kill = FALSE;
    }
    else {
        textcolor(LIGHTRED);

        (void)cprintf("Config file error: KILL command parameter! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Config_Kill_Error);
    }                   
}

/* **********************************************************************
   * Extract configuration.                                             *
   *                                                                    *
   ********************************************************************** */

static void extract_configuration(void)
{
    FILE *config;
    unsigned char *env;
    unsigned char full_path[201];
    unsigned char record[201], *atpoint;
    int loop;

/*
 * Get environment variable if there is one ad build a path
 * to the configuration file.
 */

    if (NULL == (env = getenv("UUCPRA"))) {
        (void)strcpy(full_path, "UUCP-RA.CFG");
        (void)strcpy(log_directory, "UUCP-RA.LOG");
    }
    else {
        (void)strcpy(full_path, env);
        (void)strcpy(log_directory, env);

        if (full_path[strlen(full_path) - 1] != '\\') {
            (void)strcat(full_path, "\\");
            (void)strcat(log_directory, "\\");
        }

        (void)strcat(full_path, "UUCP-RA.CFG");
        (void)strcat(log_directory, "UUCP-RA.LOG");
    }

/*
 * Open up the configuration file.
 */

    if ((config = fopen(full_path, "rt")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I was unable to find config file: %s %c%c",
            full_path, 0x0d, 0x0a);

        fcloseall();
        doexit(Missing_Config);
    }

/*
 * Extract each line and parse it out, calling the function which
 * will do the majority of the work.
 */

    while (! feof(config)) {
        (void)fgets(record, 200, config);

        if (! feof(config)) {
            atpoint = record;
            skipspace(atpoint);

            if (! strnicmp(atpoint, "system", 6)) {
                atpoint += 6;
                skipspace(atpoint);
                plug_address(atpoint, &f_zone, &f_net, &f_node, &f_point);
            }
            else if (! strnicmp(atpoint, "gate", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_address(atpoint, &g_zone, &g_net, &g_node, &g_point);
            }
            else if (! strnicmp(atpoint, "network", 7)) {
                atpoint += 7;
                skipspace(atpoint);
                plug_network_directory(atpoint);
            }
            else if (! strnicmp(atpoint, "radir", 5)) {
                atpoint += 5;
                skipspace(atpoint);
                plug_ra_directory(atpoint);
            }
            else if (! strnicmp(atpoint, "inboundfolder", 13)) {
                atpoint += 13;
                skipspace(atpoint);
                plug_inbound_folder(atpoint);
            }
            else if (! strnicmp(atpoint, "outboundfolders", 15)) {
                atpoint += 15;
                skipspace(atpoint);
                plug_outbound_folder(atpoint);
            }
            else if (! strnicmp(atpoint, "log", 3)) {
                atpoint += 3;
                skipspace(atpoint);
                plug_log_file(atpoint);
            }
            else if (! strnicmp(atpoint, "nodelist", 8)) {
                atpoint += 8;
                skipspace(atpoint);
                plug_nodelist_directory(atpoint);
            }
            else if (! strnicmp(atpoint, "origin", 6)) {
                atpoint += 6;           /* Don't! skipspace! */
                plug_origin_line(atpoint);
            }
            else if (! strnicmp(atpoint, "hold", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_hold(atpoint);
            }
            else if (! strnicmp(atpoint, "immediate", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_immediate(atpoint);
            }
            else if (! strnicmp(atpoint, "crash", 5)) {
                atpoint += 5;
                skipspace(atpoint);
                plug_crash(atpoint);
            }
            else if (! strnicmp(atpoint, "keep", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_keep(atpoint);
            }
            else if (! strnicmp(atpoint, "kludge", 6)) {
                atpoint += 6;
                skipspace(atpoint);
                plug_kludge(atpoint);
            }
            else if (! strnicmp(atpoint, "informbad", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_inform_bad(atpoint);
            }
            else if (! strnicmp(atpoint, "echo", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_echo(atpoint);
            }
            else if (! strnicmp(atpoint, "kill", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_kill(atpoint);
            }
        }
    }

    (void)fclose(config);

/*
 * Validate what we have.
 */

    if (f_zone == 0 || (f_net == 1 && f_node == 1)) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: SYSTEM command address missing or invalid! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_System_Address);
    }

    if (g_zone == 0 || (g_net == 1 && g_node == 1)) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: GATE command address missing or invalid! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_Gate_Address);
    }

    if (inbound_mail_folder == 0) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: INBOUNDFOLDER command is missing! %c%c",
            0x0d, 0x0a);

        fcloseall();
        doexit(Bad_Inbound_Folder);
    }

    if (network_directory[0] == (char)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: NETWORK command is missing! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Missing_Network);
    }

    if (remote_access_directory[0] == (char)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: RADIR command is missing! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Missing_RA_Dir);
    }

    for (loop = 0; loop < 200; loop++)
        if (outbound_folders[loop])
            return;

    textcolor(LIGHTRED);
    (void)cprintf("ERROR: OUTBOUNDFOLDERS command is missing! %c%c",
        0x0d, 0x0a);

    fcloseall();
    doexit(Missing_Outbound_Folder);
}

/* **********************************************************************
   * Tell everyone we're ready and willing to run.                      *
   *                                                                    *
   ********************************************************************** */

static void say_hello(void)
{
    textcolor(LIGHTGREEN);

    (void)cprintf("\nUUCP-RA version "
        VERSION
        " running between %d:%d/%d.%d and %d:%d/%d.%d %c%c",
        f_zone, f_net, f_node, f_point,
        g_zone, g_net, g_node, g_point, 0x0d, 0x0a);
}

/* **********************************************************************
   * Get the highest message number that's in the network mail          *
   * directory and store its value.                                     *
   *                                                                    *
   ********************************************************************** */

static void find_highest_as_needed(void)
{
    highest_mail = find_highest_message_number(network_directory);
}

/* **********************************************************************
   * Open the log file for append. If it doesn't exist, create it.      *
   *                                                                    *
   * If we can't create it, we plow through.                            *
   *                                                                    *
   ********************************************************************** */

static void open_append_create_log_file(void)
{
    if ((file_log = fopen(log_directory, "a+t")) == (FILE *)NULL) {
        if ((file_log = fopen(log_directory, "wt")) == (FILE *)NULL) {
            textcolor(LIGHTRED);

            (void)cprintf("Could not create log file: %s! %c%c",
                log_directory, 0x0d, 0x0a);

            log_file = FALSE;
            return;
        }
    }
}

/* **********************************************************************
   * Read the file into the buffer until the next 0x0d. If the string   *
   * that we get indicates a kludge line, we want to ignore it.         *
   *                                                                    *
   ********************************************************************** */

static BOOL read_line(char *record, FILE *fin)
{
    unsigned char byte;
    char *original;

/*
 * Keep a pointer to the start of the buffer so that we can
 * examine it after we're through stuffing it.
 */

    original = record;

    while (! feof(fin)) {
        byte = fgetc(fin);

        if (byte == 0x0d) {
            *record++ = 0x0d;
            *record = (char)NULL;

	    return(*original != 0x01);
        }

        if (byte != 0x0a) {
            *record++ = byte;
        }
    }

    return(FALSE);
}

/* **********************************************************************
   * See if we can extract a good name.                                 *
   *                                                                    *
   ********************************************************************** */

static void examine_for_name(char *atpoint)
{
    int count;
    char first_name[20], last_name[20];

    count = 0;

/*
 * Take up to the first 15 characters and stop when a . is found.
 * If only a first name or symbolic name is offered prior to the
 * domain, we'll take that.
 */

    while (count < 15 && *atpoint && *atpoint != '.' && *atpoint != '@')
        first_name[count++] = *atpoint++;

    first_name[count] = (char)NULL;

/*
 * If end of string or the start of domain, use what we have and return.
 */

    if (! *atpoint || *atpoint == '@') {
        (void)strcpy(message.to, first_name);
        return;
    }

/*
 * If more than 15 characters, skip ahead.
 */

    if (*atpoint != '.')
        while (*atpoint && *atpoint != '.')
            atpoint++;

/*
 * If end of string, use what we have and then return.
 */

    if (! *atpoint) {
        (void)strcpy(message.to, first_name);
        return;
    }

/*
 * Skip past the .
 */

    atpoint++;

    count = 0;

/*
 * Take up to the next 15 characters or until @ is found.
 */

    while (count < 15 && *atpoint && *atpoint != '@')
        last_name[count++] = *atpoint++;

    last_name[count] = (char)NULL;

/*
 * Whatever we get for last name, cat it with first name.
 */

    (void)strcpy(message.to, first_name);
    (void)strcat(message.to, " ");
    (void)strcat(message.to, last_name);
}

/* **********************************************************************
   * Extract the destinations name by searching for a 'To:' in the      *
   * message text. If a 'To:' is found, we take the first string of     *
   * characters, up to the . and up to 15 characters only and use it as *
   * the first name. After the . (if there is one) we take everything   *
   * up to the @ and up to 15 characters only and use it as the last    *
   * name.                                                              *
   *                                                                    *
   * If the first name is missing, we default to "UUCP." If the last    *
   * name is missing, we don't mind. We'll just use the first name.     *
   *                                                                    *
   ********************************************************************** */

static void extract_destination_name(FILE *msg_file)
{
    char record[501], *atpoint;

    while (! feof(msg_file)) {
	atpoint = record;

	if (read_line(atpoint, msg_file)) {
            skipspace(atpoint);

            if (! strnicmp(atpoint, "to:", 3)) {
                atpoint += 3;
                skipspace(atpoint);
                examine_for_name(atpoint);
                return;
            }
        }
    }
}

/* **********************************************************************
   * Put the mssage into the Remote Access data base.                   *
   *                                                                    *
   ********************************************************************** */

static void send_to_ra(FILE *msg_file, char *fname, int fsize)
{
    unsigned long seek_to;
    unsigned int result;

    seek_to = ftell(msg_file);
    extract_destination_name(msg_file);
    result = fseek(msg_file, seek_to, SEEK_SET);

    if (result != 0) {
        textcolor(LIGHTRED);

        (void)cprintf("ERROR: Seek in message toss to Remote Access failed! %c%c",
            0x0d, 0x0a);

	fcloseall();
        doexit(Seek_Failed);
    }

    toss_message_to_ra(msg_file);

    if (diag) {
        (void)printf("DIAG: Toss %s to Remote Access -> %s\n",
            fname, message.to);
    }

    if (log_file)
        make_log_entry(fname, fsize, 0);
}

/* **********************************************************************
   * See if there is a UUCP address in the following.  If there is then *
   * return TRUE else return FALSE.                                     *
   *                                                                    *
   * If the first character is a . we know it's been done.              *
   *                                                                    *
   ********************************************************************** */

static int contains_uucp_address(char *in_this)
{
    char hold_from[101], *atpoint;

    if (*in_this == '.')
        return(FALSE);

    (void)strcpy(hold_from, in_this);
    atpoint = hold_from;
    ucase(atpoint);

    if (strstr(hold_from, "UUCP") != (char *)NULL)
        return(TRUE);

    return(FALSE);
}

/* **********************************************************************
   * Examine the message that we're pointing to.                        *
   *                                                                    *
   ********************************************************************** */

static void process_this(char *fname, int fsize)
{
    char full_path[201];
    FILE *msg_file;
    char hold_from[50];

    (void)strcpy(full_path, network_directory);
    (void)strcat(full_path, fname);

    if (diag) {
        (void)printf("DIAG: Search %s\n", full_path);
    }

    if ((msg_file = fopen(full_path, "r+b")) == (FILE *)NULL) {
        textcolor(YELLOW);

        (void)cprintf("Warning: can't open file: %s! %c%c",
            full_path, 0x0d, 0x0a);

        return;
    }

    if (fread(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
        (void)fclose(msg_file);
        textcolor(YELLOW);

        (void)cprintf("Warning: can't read file: %s! %c%c",
            full_path, 0x0d, 0x0a);

        return;
    }

    if (contains_uucp_address(message.from)) {
        if (((message.attribute & Fido_Local) != Fido_Local) || testing) {
	    send_to_ra(msg_file, fname, fsize);
            moved_to_fidonet++;

            if (! want_keep) {
                (void)fclose(msg_file);
                unlink(full_path);
            }
            else {
                rewind(msg_file);

                (void)strcpy(hold_from, message.from);
                (void)strcpy(message.from, ".");
                (void)strcat(message.from, hold_from);

                if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
                    (void)fclose(msg_file);
                    textcolor(YELLOW);

                    (void)cprintf("Warning: can't update file: %s! %c%c",
                        full_path, 0x0d, 0x0a);

                    return;
                }

                (void)fclose(msg_file);
            }

            return;
        }
    }

    (void)fclose(msg_file);
}

/* **********************************************************************
   * Scan through the network mail directory for inbound mail.          *
   *                                                                    *
   ********************************************************************** */

static void scan_fidonet(void)
{
    char result;
    struct ffblk file_block;
    char full_path[101];

    textcolor(GREEN);

    (void)cprintf("    Searching UUCP -> %s %c%c",
        network_directory, 0x0d, 0x0a);

/*
 * Build the full path to search for.
 */

    (void)sprintf(full_path, "%s*.MSG", network_directory);

/*
 * See if we have at least one. If so, process it.
 */

    result = findfirst(full_path, &file_block, 0x16);

    if (! result)
        process_this(file_block.ff_name, (int)file_block.ff_fsize);

/*
 * While there are more files found, check them out as well.
 */

    while (! result) {
        result = findnext(&file_block);

        if (! result) {
            process_this(file_block.ff_name, (int)file_block.ff_fsize);
        }
    }
}

/* **********************************************************************
   * Basically, we close the Remote Access files and open them again.   *
   *                                                                    *
   * Note that we inform the get__ra__information() function that we    *
   * want to open the data base for read and update rather than for     *
   * append.                                                            *
   ********************************************************************** */

static void restart_remote_access(void)
{
    if (MSGINFO  != (FILE *)NULL) (void)fclose(MSGINFO);
    if (MSGIDX   != (FILE *)NULL) (void)fclose(MSGIDX);
    if (MSGTOIDX != (FILE *)NULL) (void)fclose(MSGTOIDX);
    if (MSGHDR   != (FILE *)NULL) (void)fclose(MSGHDR);
    if (MSGTXT   != (FILE *)NULL) (void)fclose(MSGTXT);

    get_ra_information(FALSE);
}

/* **********************************************************************
   * Scan through the Remote Access mail directory for outbound mail.   *
   *                                                                    *
   ********************************************************************** */

static void scan_remote_access(void)
{
    textcolor(GREEN);

    (void)cprintf("    Searching FidoNet -> %s %c%c",
        remote_access_directory, 0x0d, 0x0a);

    process_outbound();
}

/* **********************************************************************
   * Process the mail.                                                  *
   *                                                                    *
   ********************************************************************** */

static void process_mail(void)
{
    if (! scan_only) {
        scan_fidonet();
    }
    else {
        textcolor(LIGHTMAGENTA);

        (void)cprintf("    Not scanning for inbound Internet mail %c%c",
            0x0d, 0x0a);
    }

    restart_remote_access();

    if (! toss_only) {
        scan_remote_access();
    }
    else {
        textcolor(LIGHTMAGENTA);

        (void)cprintf("    Not scanning for outbound Internet mail %c%c",
            0x0d, 0x0a);
    }
}

/* **********************************************************************
   * Give a final report.                                               *
   *                                                                    *
   ********************************************************************** */

static void offer_final_report(void)
{
    textcolor(LIGHTMAGENTA);

    (void)cprintf("%c%cThere were %d messages moved from FidoNet ==> UUCP %c%c",
        0x0d, 0x0a, moved_to_uucp, 0x0d, 0x0a);

    textcolor(LIGHTMAGENTA);

    (void)printf("There were %d messages moved from UUCP ==> FidoNet %c%c",
        moved_to_fidonet, 0x0d, 0x0a);
}

/* **********************************************************************
   * Build a report record and then print it.                           *
   *                                                                    *
   ********************************************************************** */

static void report_this_entry(char *atpoint,
    int zone,
    int network,
    FILE *fout)
{
    char system_name[101], system_where[101];
    char sysop_name[101], system_phone[101];
    int speed, node, count;
    char sa[20], record[101];

/*
 * Extract node number, pointing past the comma first.
 */

    while (*atpoint && *atpoint != ',') atpoint++;
    if (! *atpoint) return;
    atpoint++;
    node = atoi(atpoint);

/*
 * Skip past it.
 */

    while (*atpoint && *atpoint != ',') atpoint++;
    if (! *atpoint) return;
    atpoint++;

/*
 * Get the systems name.
 */

    count = 0;
    while (*atpoint && *atpoint != ',') system_name[count++] = *atpoint++;
    system_name[count] = (char)NULL;
    if (! *atpoint) return;
    atpoint++;

/*
 * Get systems location.
 */

    count = 0;
    while (*atpoint && *atpoint != ',') system_where[count++] = *atpoint++;
    system_where[count] = (char)NULL;
    if (! *atpoint) return;
    atpoint++;

/*
 * Get sysops name.
 */

    count = 0;
    while (*atpoint && *atpoint != ',') sysop_name[count++] = *atpoint++;
    sysop_name[count] = (char)NULL;
    if (! *atpoint) return;
    atpoint++;

/*
 * Get phone number.
 */

    count = 0;
    while (*atpoint && *atpoint != ',') system_phone[count++] = *atpoint++;
    system_phone[count] = (char)NULL;
    if (! *atpoint) return;
    atpoint++;

/*
 * If phone number is unpublished, ignore it!
 */

    if (system_phone[0] < '0' || system_phone[0] > '9') return;

/*
 * Get baud rate
 */

    speed = atoi(atpoint);

/*
 * Build the report record.
 */

    (void)sprintf(sa, "%d:%d/%d", zone, network, node);
    system_name[30] = (char)NULL;
    system_where[30] = (char)NULL;

    (void)sprintf(record,
        "%-15s %-30s - %-30s\n                %s   %s  (Baud: %d)\n\n",
        sa,
        system_name, system_where, sysop_name,
        system_phone, speed);

/*
 * Write it to the output file
 */

    (void)fputs(record, fout);
}

/* **********************************************************************
   * Search through the nodelist for all of the UUCP systems which may  *
   * appear in the same zone and network that the system is running in. *
   *                                                                    *
   ********************************************************************** */

static void search_nodelist(void)
{
    FILE *fin, *fout;
    char record[201], *atpoint;
    int zone, network;
    int total_count;
    BOOL within_zone_and_network;

    total_count = 0;
    within_zone_and_network = FALSE;
    zone = network = 1;

    if (uucp_all_search)
        within_zone_and_network = TRUE;

    if (nodelist_directory[0] == (char)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("No nodelist directory was offered! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(No_Nodelist_Offered);
    }

/*
 * Open the input file containing the nodelist
 */

    if ((fin = fopen(nodelist_directory, "rt")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("Can't find nodelist file: %s! %c%c",
            nodelist_directory, 0x0d, 0x0a);

        fcloseall();
        doexit(Cant_Open_Nodelist);
    }

/*
 * Since that was successful, create the output file
 */

    if ((fout = fopen("UUCP-RA.LST", "wt")) == (FILE *)NULL) {
        textcolor(LIGHTRED);

        (void)cprintf("I can't create file: UUCP-RA.LST! %c%c", 0x0d, 0x0a);
        fcloseall();
        doexit(Cant_Create_List_File);
    }

/*
 * Go through the nodelist
 */

    while (! feof(fin)) {
        (void)fgets(record, 200, fin);
        atpoint = record;

        ucase(atpoint);

        if (! feof(fin)) {
            if (! strnicmp(atpoint, "zone", 4)) {
                atpoint += 5;
                zone = atoi(atpoint);
                atpoint--;

                if ((! uucp_all_search) && within_zone_and_network) {
                    if (zone != f_zone) {
                        (void)fclose(fin);

                        textcolor(LIGHTMAGENTA);

                        (void)cprintf("%c%cThere were %d entries located %c%c",
                            0x0d, 0x0a, total_count, 0x0d, 0x0a);

                        textcolor(LIGHTMAGENTA);

                        (void)cprintf("The result has been placed in file: UUCP-RA.LST %c%c",
                            0x0d, 0x0a);

                        (void)fclose(fin);
                        (void)fclose(fout);
                        return;
                    }
                }
            }

            if (! strnicmp(atpoint, "host", 4) ||
                    !strnicmp(atpoint, "region", 6)) {

                if (! strnicmp(atpoint, "region", 6)) {
                    atpoint += 7;
                }
                else {
                    atpoint += 5;
                }

                network = atoi(atpoint);
                atpoint--;

		if ((! uucp_all_search) && within_zone_and_network) {
                    if (network != f_net) {
                        (void)fclose(fin);

                        textcolor(LIGHTMAGENTA);

                        (void)cprintf("%c%cThere were %d entries located %c%c",
                            0x0d, 0x0a, total_count, 0x0d, 0x0a);

                        textcolor(LIGHTMAGENTA);

                        (void)cprintf("The result has been placed in file: UUCP-RA.LST %c%c",
                            0x0d, 0x0a);

                        (void)fclose(fin);
                        (void)fclose(fout);
                        return;
                    }
                }
            }

            if (! within_zone_and_network) {
		if (zone == f_zone && network == f_net) {
                    within_zone_and_network = TRUE;
                }
            }

            if (strstr(record, "GUUCP") != (char *)NULL) {
                if (within_zone_and_network) {
                    report_this_entry(atpoint, zone, network, fout);
                    total_count++;
                }
            }    
            else if (strstr(record, ",UUCP") != (char *)NULL) {
                if (within_zone_and_network) {
                    report_this_entry(atpoint, zone, network, fout);
                    total_count++;
                }
            }                         
        }
    }

    (void)fclose(fin);
    (void)fclose(fout);
    textcolor(LIGHTMAGENTA);

    (void)cprintf("%c%cThere were %d entries located%c%c",
        0x0d, 0x0a, total_count, 0x0d, 0x0a);

    textcolor(LIGHTMAGENTA);

    (void)printf("The result has been placed in file: UUCP-RA.LST %c%c",
        0x0d, 0x0a);
}

/* **********************************************************************
   * The main entry point.                                              *
   *                                                                    *
   ********************************************************************** */

void main(int argc, char *argv[])
{
    int loop;

    initialize_module();

    for (loop = 1; loop < argc; loop++) {
        if (! strnicmp(argv[loop], "/diag", 5)) {
            diag = TRUE;
        }
        else if (! strnicmp(argv[loop], "/test", 5)) {
            testing = TRUE;
        }
        else if (! strnicmp(argv[loop], "/list", 5)) {
            uucp_search = TRUE;

            if (! strnicmp(argv[loop], "/listall", 8)) {
                uucp_all_search = TRUE;
            }
        }
        else if (! strnicmp(argv[loop], "/toss", 5)) {
            toss_only = TRUE;
        }
        else if (! strnicmp(argv[loop], "/scan", 5)) {
            scan_only = TRUE;
        }
    }

    extract_configuration();
    say_hello();

    if (uucp_search) {
        search_nodelist();
        fcloseall();
        doexit(No_Problem);
    }

    if (log_file)
        open_append_create_log_file();

    find_highest_as_needed();

    get_ra_information(TRUE);

    process_mail();

    if (log_file)
        (void)fclose(file_log);

    offer_final_report();
    fcloseall();

    if (moved_to_uucp != 0 && moved_to_fidonet != 0) {
        doexit(Toss_Both_Out_In_Bound);
    }

    if (moved_to_uucp != 0) {
        doexit(Toss_To_Outbound);
    }

    if (moved_to_fidonet != 0) {
        doexit(Toss_To_Inbound);
    }

    doexit(No_Problem);
}


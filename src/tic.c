#include<stdio.h>
#include<conio.h>
#include<stdlib.h>
#include <windows.h>

int board[10] = {2,2,2,2,2,2,2,2,2,2};
int turn = 1,flag = 0;
int player,comp;

void menu();
void go(int n);
void start_game();
void check_draw();
void draw_board();
void player_first();
void put_X_O(char ch,int pos);
COORD coord= {0,0}; // this is global variable
//center of axis is set to the top left cornor of the screen
void gotoxy(int x,int y)
{
    coord.X=x;
    coord.Y=y;
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),coord);
}

void main()
{
    system("cls");
    menu();
    getch();

}

void menu()
{
    int choice;
    system("cls");
    printf("\n--------MENU--------");
    printf("\n1 : Play with X");
    printf("\n2 : Play with O");
    printf("\n3 : Exit");
    printf("\nEnter your choice:>");
    scanf("%d",&choice);
    turn = 1;
    switch (choice)
    {
    case 1:
        player = 1;
        comp = 0;
        player_first();
        break;
    case 2:
        player = 0;
        comp = 1;
        start_game();
        break;
    case 3:
        exit(1);
    default:
        menu();
    }
}
int make1()
{
	int me = turn % 2 ? 3 : 5;
	int him = turn % 2 ? 5 : 3;
	if (turn == 1)
		return 5;
	if (turn == 2) {
		// there should only be one spot marked. Find it
		// and return the proper spot to move to.
		if (board[5] != 2)
			return 1;
		return 5;
	}
	if (turn == 3) {
		if (board[8] == him)
			return 4; // make2() handles all other situations
	}
	if (turn == 4) {
		if (board[1] == me && board[5] == him && board[9] == him)
			return 3;
	}
	// here we look for a winnable situation.
	if (board[5] == me) {
		if (board[4]==me&&board[1]==2&&board[3]==2&&board[7]==2)
			return 7;  // we will win.
		if (board[4]==me&&board[1]==2&&board[7]==2&&board[9]==2)
			return 1;  // we will win.
		if (board[2]==me&&board[1]==2&&board[3]==2&&board[7]==2)
			return 3;  // we will win.
		if (board[2]==me&&board[1]==2&&board[3]==2&&board[9]==2)
			return 1;  // we will win.
		if (board[6]==me&&board[3]==2&&board[7]==2&&board[9]==2)
			return 3;  // we will win.
		if (board[6]==me&&board[1]==2&&board[3]==2&&board[9]==2)
			return 9;  // we will win.
		if (board[8]==me&&board[3]==2&&board[7]==2&&board[9]==2)
			return 7;  // we will win.
		if (board[8]==me&&board[1]==2&&board[7]==2&&board[9]==2)
			return 9;  // we will win.
	} else {
		if (board[2]==me&&board[4]==me&&board[1]==2&&board[3]==2&&board[7]==2)
			return 1;  // we will win.
		if (board[2]==me&&board[6]==me&&board[1]==2&&board[3]==2&&board[9]==2)
			return 3;  // we will win.
		if (board[8]==me&&board[6]==me&&board[3]==2&&board[9]==2&&board[7]==2)
			return 9;  // we will win.
		if (board[8]==me&&board[4]==me&&board[9]==2&&board[7]==2&&board[1]==2)
			return 7;  // we will win.
	}
	// ok, now look for the player to have some winning possible, and if so, block it.
	if (board[5] == him) {
		if (board[4]==him&&board[1]==2&&board[3]==2&&board[7]==2)
			return 7;  // we will win.
		if (board[4]==him&&board[1]==2&&board[7]==2&&board[9]==2)
			return 1;  // we will win.
		if (board[2]==him&&board[1]==2&&board[3]==2&&board[7]==2)
			return 3;  // we will win.
		if (board[2]==him&&board[1]==2&&board[3]==2&&board[9]==2)
			return 1;  // we will win.
		if (board[6]==him&&board[3]==2&&board[7]==2&&board[9]==2)
			return 3;  // we will win.
		if (board[6]==him&&board[1]==2&&board[3]==2&&board[9]==2)
			return 9;  // we will win.
		if (board[8]==him&&board[3]==2&&board[7]==2&&board[9]==2)
			return 7;  // we will win.
		if (board[8]==him&&board[1]==2&&board[7]==2&&board[9]==2)
			return 9;  // we will win.
	} else {
		if (board[2]==him&&board[4]==him&&board[1]==2&&board[3]==2&&board[7]==2)
			return 1;  // block his win.
		if (board[2]==him&&board[6]==him&&board[1]==2&&board[3]==2&&board[9]==2)
			return 3;  // block his win.
		if (board[8]==him&&board[6]==him&&board[3]==2&&board[9]==2&&board[7]==2)
			return 9;  // block his win.
		if (board[8]==him&&board[4]==him&&board[9]==2&&board[7]==2&&board[1]==2)
			return 7;  // block his win.
	}
	return 0;
}
int make2()
{
    if(board[5] == 2)
        return 5;
    if(board[2] == 2)
        return 2;
    if(board[4] == 2)
        return 4;
    if(board[6] == 2)
        return 6;
    if(board[8] == 2)
        return 8;
    return 0;
}

int make4()
{
    if(board[1] == 2)
        return 1;
    if(board[3] == 2)
        return 3;
    if(board[7] == 2)
        return 7;
    if(board[9] == 2)
        return 9;
    return 0;
}

int posswin(int p)
{
// p==1 then X   p==0  then  O
    int i;
    int check_val,pos;

    if(p == 1)
        check_val = 18;
    else
        check_val = 50;

    i = 1;
    while(i<=9)//row check
    {
        if(board[i] * board[i+1] * board[i+2] == check_val)
        {
            if(board[i] == 2)
                return i;
            if(board[i+1] == 2)
                return i+1;
            if(board[i+2] == 2)
                return i+2;
        }
        i+=3;
    }

    i = 1;
    while(i<=3)//column check
    {
        if(board[i] * board[i+3] * board[i+6] == check_val)
        {
            if(board[i] == 2)
                return i;
            if(board[i+3] == 2)
                return i+3;
            if(board[i+6] == 2)
                return i+6;
        }
        i++;
    }

    if(board[1] * board[5] * board[9] == check_val)
    {
        if(board[1] == 2)
            return 1;
        if(board[5] == 2)
            return 5;
        if(board[9] == 2)
            return 9;
    }

    if(board[3] * board[5] * board[7] == check_val)
    {
        if(board[3] == 2)
            return 3;
        if(board[5] == 2)
            return 5;
        if(board[7] == 2)
            return 7;
    }
    return 0;
}

void go(int n)
{
    if(turn % 2)
        board[n] = 3;
    else
        board[n] = 5;
    turn++;
}

void player_first()
{
    int pos;

    check_draw();
    draw_board();
    gotoxy(30,18);
    printf("Your Turn :> ");
    scanf("%d",&pos);

    if(board[pos] != 2)
        player_first();

    if(pos == posswin(player))
    {
        go(pos);
        draw_board();
        gotoxy(30,20);
        //textcolor(128+RED);
        printf("Player Wins");
        getch();
        exit(0);
    }

    go(pos);
    draw_board();
    start_game();
}

void start_game()
{
// p==1 then X   p==0  then  O
    if(posswin(comp))
    {
        go(posswin(comp));
        flag = 1;
    }
    else if(posswin(player))
        go(posswin(player));
    else if (make1())
		go(make1());
	else if(make2())
        go(make2());
    else
        go(make4());
    draw_board();

    if(flag)
    {
        gotoxy(30,20);
        //textcolor(128+RED);
        printf("Computer wins");
        getch();
    }
    else
        player_first();
}

void check_draw()
{
    if(turn > 9)
    {
        gotoxy(30,20);
        //textcolor(128+RED);
        printf("Game Draw");
        getch();
        exit(0);
    }
}

void draw_board()
{
    int j;

    for(j=9; j<17; j++)
    {
        gotoxy(35,j);
        printf("|       |");
    }
    gotoxy(28,11);
    printf("-----------------------");
    gotoxy(28,14);
    printf("-----------------------");

    for(j=1; j<10; j++)
    {
        if(board[j] == 3)
            put_X_O('X',j);
        else if(board[j] == 5)
            put_X_O('O',j);
    }
}

void put_X_O(char ch,int pos)
{
    int m;
    int x = 31, y = 10;

    m = pos;

    if(m > 3)
    {
        while(m > 3)
        {
            y += 3;
            m -= 3;
        }
    }
    if(pos % 3 == 0)
        x += 16;
    else
    {
        pos %= 3;
        pos--;
        while(pos)
        {
            x+=8;
            pos--;
        }
    }
    gotoxy(x,y);
    printf("%c",ch);
}

#include <stdio.h>
#include <stdlib.h>
#if !defined (_MSC_VER)
#include <unistd.h>
#endif
#include <math.h>
#include <string.h>

#define C2I(c) ((unsigned int)(unsigned char)(c))

unsigned int * proba1;
unsigned int * proba2;
unsigned int * first;

int main(int argc, char * * argv)
{
	FILE * fichier;
	char * ligne;
	int i;
	int j;
	int np;
	int npflag;
	int args;
	unsigned int nb_lignes;
	unsigned int nb_lettres;

	FILE * statfile;

	if( (argc!=3) && (argc!=4) )
	{
		fprintf(stderr, "Usage: %s [-p] dictionnary_file statfile\n\t-p: do use non printable characters\n", argv[0]);
		return -1;
	}

	if(argc==4)
	{
		if(strcmp(argv[1], "-p"))
		{
			fprintf(stderr, "Usage: %s [-p] dictionnary_file statfile\n\t-p: do use non printable characters\n", argv[0]);
			return -1;
		}
		args = 1;
		npflag = 1;
	}
	else
	{
		args = 0;
		npflag = 0;
	}

	fichier = fopen(argv[1+args], "r");
	if(!fichier)
	{
		fprintf(stderr, "could not open %s\n", argv[1+args]);
		return -1;
	}

	first = malloc( sizeof(int) * 256 );

	ligne = malloc(4096);

	proba2 = malloc(sizeof(unsigned int) * 256 * 256);
	proba1 = malloc(sizeof(unsigned int) * 256 );
	memset(proba2, 0, sizeof(unsigned int) * 256 * 256);
	memset(proba1, 0, sizeof(unsigned int) * 256 );

	statfile = fopen(argv[2+args], "w");

	nb_lignes = 0;
	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
			continue;
		i = strlen(ligne)-1;
		while( (i>0) && ((ligne[i]=='\n') || (ligne[i]=='\r')) )
		{
			ligne[i]=0;
			i--;
		}
		for(i=0;ligne[i];i++)
		{
			np = 0;
			if(C2I(ligne[i])<32)
			{
				if (!npflag) fprintf(stderr, "Warning, non printable character line %d : %s\n", nb_lignes, ligne);
				np += 1;
			}
			if(C2I(ligne[i])>127)
			{
				if (!npflag) fprintf(stderr, "Warning, non US ascii character line %d : %s\n", nb_lignes, ligne);
				np += 1;
			}
			if((i>0) && (C2I(ligne[i-1])<32))
			{
				np += 2;
			}
			if((i>0) && (C2I(ligne[i-1])>127))
			{
				np += 2;
			}

			if( (i==0) && ((np == 0) || (npflag == 1)) )
				proba1[C2I(ligne[0])]++;
			if( (i>0) && ((np == 0) || (npflag == 1)) )
				proba2[C2I(ligne[i-1])*256 + C2I(ligne[i])]++;
		}
		nb_lignes++;
	}

	for(i=0;i<256;i++)
	{
		if ( (proba1[i] == 0 ) || (i==0) )
		{
			proba1[i] = 1000;
		}
		else
		{
			if( (unsigned int) (- 10*log( (double) proba1[i] / (double) nb_lignes )) == 0)
			{
				fprintf(stderr, "zero -10*log proba1[%d] (%d) / %d converted to 1\n", i, proba1[i], nb_lignes);
				proba1[i] = 1;
			}
			else
				proba1[i] = (unsigned int) (- 10*log( (double) proba1[i] / (double) nb_lignes ));
			fprintf(statfile, "%d=proba1[%d]\n", proba1[i], i);
		}

		/* premiere passe : nb lettres */
		nb_lettres = 0;
		for(j=0;j<256;j++)
		{
			nb_lettres += proba2[i*256 + j];
		}

		first[i] = 255;

		/* maintenant, calcul des stats */
		for(j=0;j<256;j++)
		{
			if( proba2[i*256 + j] == 0 )
			{
				proba2[i*256 + j] = 1000;
			}
			else
			{
				if(first[i] == 255)
					first[i] = j;
				if((unsigned int) (- 10*log( (double) proba2[i*256+j] / (double) nb_lettres )) == 0)
				{
					fprintf(stderr, "zero -10*log proba2[%d*256+%d] (%d) / %d, converted to 1 to prevent infinite length candidates\n", i, j, proba2[i*256+j],nb_lettres );
					proba2[i*256 + j] = 1;
				}
				else
				{
					proba2[i*256 + j] = (unsigned int) (- 10*log( (double) proba2[i*256+j] / (double) nb_lettres ));
				}
				fprintf(statfile, "%d=proba2[%d*256+%d]\n", proba2[i*256+j], i, j);
			}
		}
	}

	fclose(statfile);

	free(proba1);
	free(proba2);

	free(first);

	free(ligne);
	fclose(fichier);

	return 0;
}

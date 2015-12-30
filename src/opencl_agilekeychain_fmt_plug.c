/* 1Password Agile Keychain cracker patch for JtR. Hacked together during
 * July of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net> and
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>, and it is
 * hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is based on "agilekeychain" project but no actual code is
 * borrowed from it.
 *
 * "agilekeychain" project is at https://bitbucket.org/gwik/agilekeychain
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_agilekeychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_agilekeychain);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "stdint.h"
#include "misc.h"
#include "aes.h"
#include "common-opencl.h"
#include "options.h"
#include "jumbo.h"

#define FORMAT_LABEL		"agilekeychain-opencl"
#define FORMAT_NAME		"1Password Agile Keychain"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL AES"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN		4
#define SALTLEN			8
#define CTLEN			1040

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keychain_password;

typedef struct {
	uint32_t v[16/4];
} keychain_hash;

typedef struct {
	int iterations;
	int outlen;
	uint8_t length;
	uint8_t salt[SALTLEN];
} keychain_salt;

static int *cracked;
static int any_cracked;

static struct fmt_tests keychain_tests[] = {
	{"$agilekeychain$2*1000*8*7146eaa1cca395e5*1040*e7eb81496717d35f12b83024bb055dec00ea82843886cbb8d0d77302a85d89b1d2c0b5b8275dca44c168cba310344be6eea3a79d559d0846a9501f4a012d32b655047673ef66215fc2eb4e944a9856130ee7cd44523017bbbe2957e6a81d1fd128434e7b83b49b8a014a3e413a1d76b109746468070f03f19d361a21c712ef88e05b04f8359f6dd96c1c4487ea2c9df22ea9029e9bc8406d37850a5ead03062283a42218c134d05ba40cddfe46799c931291ec238ee4c11dc71d2b7e018617d4a2bf95a0c3c1f98ea14f886d94ee2a65871418c7c237f1fe52d3e176f8ddab6dfd4bc039b6af36ab1bc9981689c391e71703e31979f732110b84d5fccccf59c918dfcf848fcd80c6da62ced6e231497b9cbef22d5edca439888556bae5e7b05571ac34ea54fafc03fb93e4bc17264e50a1d04b688fcc8bc715dd237086c2537c32de34bbb8a29de0208800af2a9b561551ae6561099beb61045f22dbe871fab5350e40577dd58b4c8fb1232f3f85b8d2e028e5535fd131988a5df4c0408929b8eac6d751dcc698aa1d79603251d90a216ae5e28bffc0610f61fefe0a23148dcc65ab88b117dd3b8d311157424867eb0261b8b8c5b11def85d434dd4c6dc7036822a279a77ec640b28da164bea7abf8b634ba0e4a13d9a31fdcfebbdbe53adcdf2564d656e64923f76bc2619428abdb0056ce20f47f3ece7d4d11dc55d2969684ca336725561cb27ce0504d57c88a2782daccefb7862b385d494ce70fef93d68e673b12a68ba5b8c93702be832d588ac935dbf0a7b332e42d1b6da5f87aed03498a37bb41fc78fcdbe8fe1f999fe756edf3a375beb54dd508ec45af07985f1430a105e552d9817106ae12d09906c4c28af575d270308a950d05c07da348f59571184088d46bbef3e7a2ad03713e90b435547b23f340f0f5d00149838d9919d40dac9b337920c7e577647fe4e2811f05b8e888e3211d9987cf922883aa6e53a756e579f7dff91c297fcc5cda7d10344545f64099cfd2f8fd59ee5c580ca97cf8b17e0222b764df25a2a52b81ee9db41b3c296fcea1203b367e55d321c3504aeda8913b0cae106ccf736991030088d581468264b8486968e868a44172ad904d97e3e52e8370aaf52732e6ee6cc46eb33a901afc6b7c687b8f6ce0b2b4cdfe19c7139615195a052051becf39383ab83699a383a26f8a36c78887fe27ea7588c0ea21a27357ff9923a3d23ca2fb04ad671b63f8a8ec9b7fc969d3bece0f5ff19a40bc327b9905a6de2193ffe3aa1997e9266205d083776e3b94869164abcdb88d64b8ee5465f7165b75e1632abd364a24bb1426889955b8f0354f75c6fb40e254f7de53d8ef7fee9644bf2ebccd934a72bb1cc9c19d354d66996acbddd60d1241657359d9074a4b313b21af2ee4f10cf20f4122a5fad4ee4f37a682ffb7234bea61985d1ad130bfb9f4714461fb574dbf851c*1000*8*c05f3bc3e7f3cad7*1040*f3e3d091b64da1529b04b2795898b717faad59f7dae4bda25e6e267c28a56a7702e51991b2a3fb034cdda2d9bfd531dfd2c3af00f39fdfe8bcbdde02ab790415bcf071d133b15f647f55ff512730ae4914ce20b72184c827f6350ac768b00c9eab0e3322e084bb3e9e9439a10030950f5504dcc4f7ba614b27fde99bd0d743a58341e90ec313395486eb8068df205b7bdf25134ed97dd2e2883d7eb3e63b659602ada765084a69d7ed8fc55b60aa67718cc9e5bf31ab8f3029b32a4b001071848d2b76b5f4b921d2169ca287e9e78ecd904d040c817c7c7cde4ba8510b462e139c16519962ca0adb7d5f89d431cd4541a9a7aaec8d799697f4d3947d87884bed32ada13db725c72ab6450ac8fe989a94917cca784bcf6ffbe756f19d4e8897e0f80d8c318e13e5b30fc356646aaf038a952b0781f12dfef1f4bd6922ae05a573eeff4dbb064cfbb0fd62962a6a53a8de308da2b8e83baebfe261cb127f874a5eff3f05cda123ab2ba559cf444ce33b6845f4c902733b8982044151a8aa1859769082ade5928f2d4f616ce972ae8dde1f2be37d496ad16057008dfe678c75cbdc53db25ed311edbcf8b2a73bcd2809f6bd1d389aaeed82a75fa15676d08aa5390efdc189c180be6a52ec5a7371304d26e477039197671377d1ea3d6ee41e68a42348a4fe9a1d2400eaeba8ed0a7419b9694d780456d96378c00318a5be0f41afa887476b3bebb7cf30d61ca8fc77de35671a3053a517aa39444e01e1752da3146dc97eec5849d6f025c3d4bc6e0499b901f629d8a081ad35ed33602cbef5e9a68f090170fcc1f285eb094e3dc619740a067fd2aeeb20abbb17926c3ad097f3f0bad4de540d1829a985cd7e700100622ec47da046071c11a1597e5f093268b4ed79ffcf2450b9ba2b649b932fbce912bdb4da010581bd9c731be792c8f75177f6c8c4e1756d63a1491a8aae4bb11beeca118e7d08073b500dd82b81e4bdbeb15625afca8f1c8e06b2360da972587516ef62e91d1d9aad90e62226d53363bff318f5af21f69c234731ac22b09506a1b807d2366e88905668d960c7963daa93046e9a56db1d7a437e9a37aa7a2945197265478b264ec14d383030ef73504fd26d4be9e72ebddb14a00bf6bd66a3adaa1d17cada378a2b0bc852f961af52333f7966f8a60738dfd47e79ce537082f187117ffd31f54f53356b671154dfa245671c4cd054c1a8d303a202fccfae6d3f9e3646838cef38703b5e660b5ce7679f5898d801908f90092dbec335c98e4002041287fe9bfa7d7828a29ab240ec2cedc9fa12cfd7c3ef7b61dad4fbf2ef9c0a904dbde1b3792fb5178607608dc9fc2fbc85addf89fa3df94317e729810b508356b5bb176cdb022afb0ec5eeff4d5081b66733d1be1b54cc4f080bfc33187663b5ab185472b35dc8812e201472e6af376c43ee23aa2db6cd04bddd79b99b0c28c48a5ae", "openwall"},
	{"$agilekeychain$1*1000*8*54434b3047723444*1040*316539685a36617546544a61466e35743970356559624464304467394a4a41615459594a6b66454c5462417a7a694b5751474e4748595036344f3945374b414b676b6b7278673658794e63734a316c48656b496a3156346a544c6861797537347032466b4d6b416d31704a6b5063547a44703152544f72696e6e38347732597672774f6476414c70346462595a7678656b6e5958716b7a61746d5874514e575965564735627a437578584e4a573050567939413073306c377a4d726e6d576a6655424455394f4934696c48454f4d536e635567393950686d4171364f76747749446130454c6d74783069704d30456d45374f56736e486a5534667877327a526e52596e55454452393544437042646e6739355938714836584968664c4d7a726a4f63544c6858385141464c71565463664270493761664d633055447879613169456a72664479346438305641417054754775477a475266766c4774543668673848624d31636c37624e73743549634457655375507138535139396c4c39364c4f6f757a43305535586161364b47676a61713971394459526a78744e547459797a6a57715a3575534364487a4430306d4e4e39483277674c733238726463616d4f5146467957374234727252774b6d6161664b6d67414d5854496444665848684c376c6c776d47477a4b57566d5a3646346e775441446f3659745038646d336b6370494d50676742797a41325630716e794833793237494152496477556e4d6c4751497367346672635364486e6e71504f6e6264575953584462586c6e573947347a567163535333366e3253504d65656b45483841544f6952384d6170724471706c4a307863713653707265624f544a4d5139377562454a334b776e4879746a37704e37694557484d69696d436f484973613443754d484b4f51484833545a364654694a6d31783061665536796c444f7257666964397243444f684d305a324c6b75693953716664354b435963703559354978757a64354a755158394136663744435a674e4c73484a7935737a707739724c783077316631637349757a6d696252576244396a537730593143633348385a775734534b646569684f634f4c35323364734b7179625750364b76344a4a56626c4f727069366f575a386432745375684c464e42643173445a6a50745743696e666a4458325058644d57654c596d326f5763516a7951524a566372354d4d58435877765172596b734c59354476455156746d75504830444a4e47624e31524f4d544b4a6b4d675835305a7a56736758794c475057714e78496452725269484c75424f4d6d793550677277727453597045566e304c5642764c5a6732504c7a4e71584c4c67634979637369554a3446497655795a78583547306b365a4e337477786c7961796b4d787463796971596f516fcb3584235d7ecde5f8b7bc2b8f1e9e2e*46c3b75f6e4cf139e92f683f32107271", "123"},
	{"$agilekeychain$1*1000*8*7a697868444e7458*1040*773954704874444d4d523043546b44375135544f74675a754532624a45794848305949436e4e724d336c524c39316247426a7843317131614152736d50724c6474586a4d4d445954786c31376d363155437130777a414d36586c7045555457424a5a436a657541456742417961654472745a73576e4b7a7a344d547043567846526655524b4339573631756f3850465a3878306b7176644c4253787071764c58376e716a50674f526d4a4e4b546e3359575175614b304a3964756f756935675a77544f4e6770654855776f79553465786e41364d6376496b7651624762424d62756746796a6753514c37793069783869683773454c533559365946584f545246616d48495730464e634d42466e51367856797a4368517335674a755972434b545944633270764e54775879563542776675386b6e4462506b743138694a756d63447134745361526a32373167366e787375514e346a73574e77796b4b49376d3677653448754c364b5a41514633626e71786130634458544e484a436551386e7679304b786d73346f774a383268665167596b466e39317a307269714434546d4d6173416e344b6a74455a584846526a6659746742504262495958386336755241386c496633417666696d7a5036425745757461736b684574794a5230436d50466d4b536375764674674562315679766a43453077356e614b476d345849395a726b7037626153496b6a66634f355261795157645941487731516f564c6764516d4e3074394b3839526341626f6b6b38324465497068624553646f4177786e6f68347779523338394f4e6561315271635236374d424d695978304b336b4a6966776e74614f4b43483237434b596a6630774e79394a4b7153714a48616b4b364455596a454b31433767786a72303450706d44666373574c5a61324f335852474b756c456b76483349754e3156654f417342324d6f75346d4b78774e43424863566e344c4c6c6c6d4e446b617550415a6f3337764f55484b4156344d4769336267344f4737794c354c5567636a565a6b7369616730383377744d69513431333032305a4a3747794944714d67396a5651444132424e79507a34726d346c333552757a764b6c543073437562534376714f346a5939784a546f683358517348623378716677313231383261685357743236455a6a6b6674365870554642386436574c374430635177347278736a744a6e463530756365684c7779497557366550356936514e704e4863353863437165397163496146794a726555714c623438543235396371416154326c66375276746e3550727453306b7042335961364239586c3359384b464865564e677636537234414e4d6c55583867456376686e43646e6e776a6f656d7152613453725148503462744b4a334565714f6e624a774a65623258552fff2bf0505a0bc88b9cbc9073a74586*a6f6556c971bd3ad40b52751ba025713", ""},
	{"$agilekeychain$1*1000*8*7a65613743636950*1040*524a397449393859696b4a576e437763716a574947544a6d306e32474442343355764a7a6948517a45686d7569636631514745347448424e4e6b32564239656a55596f724671547638736d4e66783949504b6f38746b6f49426d4d6b794c7a6d3077327639365a4b515934357774664a477247366b5539486135495863766845714146317458356b725a6a50376f726e55734b3136533756706a4b42516165656a50336e4558616450794f59506f4771347268454730784555485a4f5a4772526a76354f45417470616258375a386436474b366f7653583257335939516d4f5364446a414b674e467a31374f716d73516b3362795776305a414a314f63324d616a6c6472413939443879414c523733794c47467654734d7a6a4734733461674353357a4456527841486233646d446e797448696837377364784344704831784f6a5975666168626b5534796678576c59584d4b3448704a784a4f675a6d7672636b5a4b567071445a345a376648624b55414b7262694972384531336c7a6875725a6f44627571775361774b66417743336230614e4166564954334a6c3477666b4254374f747565394b32667266566d3263416a656c79416c45724b3035504a4e42307a33303632483466664272705765415a4f3552416a36544e5a54415a5976666a4b53675a68493071394a6563426964544a4f564d304a773976394944444339516e564a78587539366974586c4f6132717937354c554b65384b7638585132596832417a5271314e4b5653766d4d50506d3554463762763961554e45695a51436e79504f6e7146617a755231373574455365305446624c636450424a43526a49384b32365967496a734c324e525574526e36714c533065694f536c6c37795a456945476d4a6e327262646942416c485046616e384e4d7869427571777355714e7638305267537752726245696c734d68664b53793836684b39445a716b47546d4b59747176474c6b6a6d52513368796b367a356449706c64385541614236546e426a6b4f64766d33493972763941765a71776345686b734c594a7254446c796f46444b6d557441305a636b414e437245587a63487a30304c50564e4e73694d634d5a6f4f74414534424f53685879374e62545734487a555054774a7056686f6a7453666a664e696d354548345631374c61396862586659666332304e465a5678656a304b4d59586d586547634d67474c6d31794a4b546473474c755a697579625779503259726d6d5248544f6f704b575046556e3438415a48474168396d787136327230367248774e73493439693049794b3765314b4f74547265556c564b6e6d594a5959355a7476334b546f75375a6a676c755a557a39744b54747745583948314a37366e6c6d5a53345079555856696438336876596141617a394438711ee66b990b013609582733309b01df00*444f4656a5ec58e8a75204fb25fd5ae5", "PASSWORD"},
	{NULL}
};

static struct custom_salt {
	unsigned int nkeys;
	unsigned int iterations[2];
	unsigned int saltlen[2];
	unsigned char salt[2][SALTLEN];
	unsigned int ctlen[2];
	unsigned char ct[2][CTLEN];
} *cur_salt;

static cl_int cl_error;
static keychain_password *inbuffer;
static keychain_hash *outbuffer;
static keychain_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
size_t insize, outsize, settingsize, cracked_size;
static struct fmt_main *self;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(keychain_password) * gws;
	outsize = sizeof(keychain_hash) * gws;
	settingsize = sizeof(keychain_salt);
	cracked_size = sizeof(*cracked) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	cracked = mem_calloc(1, cracked_size);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(outbuffer->v));
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "derive_key", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(keychain_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	int ctlen;
	int saltlen;
	char *p;

	if (strncmp(ciphertext,  "$agilekeychain$", 15) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 15;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* nkeys */
		goto err;
	if (!isdec(p))
		goto err;
	if (atoi(p) > 2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	saltlen = atoi(p);
	if(saltlen > SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if(hexlenl(p) != saltlen * 2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ct length */
		goto err;
	if (!isdec(p))
		goto err;
	ctlen = atoi(p);
	if (ctlen > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if(hexlenl(p) != ctlen * 2)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));

	ctcopy += 15;	/* skip over "$agilekeychain$" */
	p = strtokm(ctcopy, "*");
	cs.nkeys = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations[0] = atoi(p);
	p = strtokm(NULL, "*");
	cs.saltlen[0] = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.saltlen[0]; i++)
		cs.salt[0][i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.ctlen[0] = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.ctlen[0]; i++)
		cs.ct[0][i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltlen[0]);
	currentsalt.length = cur_salt->saltlen[0];
	currentsalt.iterations = cur_salt->iterations[0];
	currentsalt.outlen = 16;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int akcdecrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[CTLEN];
	int n, key_size;
	AES_KEY akey;
	unsigned char iv[16];

	memcpy(iv, data + CTLEN - 32, 16);

	if (AES_set_decrypt_key(derived_key, 128, &akey) < 0)
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");

	AES_cbc_encrypt(data + CTLEN - 16, out + CTLEN - 16, 16, &akey, iv, AES_DECRYPT);

	n = check_pkcs_pad(out, CTLEN, 16);
	if (n < 0)
		return -1;

	key_size = n / 8;
	if (key_size != 128 && key_size != 192 && key_size != 256)
		// "invalid key size"
		return -1;

	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
	        "Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (!akcdecrypt((unsigned char*)outbuffer[index].v, cur_salt->ct[0]))
	{
		cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations[0];
}

struct fmt_main fmt_opencl_agilekeychain = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{
			"iteration count",
		},
		keychain_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */

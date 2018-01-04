/*
 * Common code for the NetIQ SSPR format.
 */

static struct fmt_tests sspr_tests[] = {
	{"$sspr$1$100000$NONE$64840051a425cbc0b4e2d3750d9e0de3e800de18", "password@12345"},
	{"$sspr$1$100000$NONE$5cd2aeb3adf2baeca485672f01486775a208a40e", "openwall@12345"},
	{"$sspr$2$100000$tMR6sNepv6M6nOqOy3SWnAUWo22p0GI7$f0ae3140ce2cf46c13d0b6c4bd4fab65b45b27c0", "openwall@123"},
	{"$sspr$2$100000$BrWV47lSy3Mwpp8pb60ZlJS85YS242bo$1f71c58c8dfc16c9037d3cd1cf21d1139cad4fa4", "password@123"},
	{"$sspr$3$100000$blwmhFBUiq67iEX9WFc8EG8mCxWL4tCR$c0706a057dfdb5d31d6dd40f060c8982e1e134fdf1e7eb0d299009c2f56c1936", "hello@12345"},
	{"$sspr$3$100000$lNInqvnmbv9x65N2ltQeCialILG8Fr47$6bd508dcc2a5626c9d7ab3296bcce0538ca0ba24bf43cd2aebe2f58705814a00", "abc@123"},
	{"$sspr$4$100000$ZP3ftUBQwrovglISxt9ujUtwslsSMCjj$a2a89e0e185f2a32f18512415e4dfc379629f0222ead58f0207e9c9f7424c36fe9c7a615be6035849c11da1293da78e50e725a664b7f5fe123ede7871f13ae7f", "hello@123"},
	{"$sspr$4$100000$ZzhxK3gHP8HVkcELqIeybuRWvZjDirtg$ca5608befc50075bc4a1441de23beb4a034197d70df670addabc62a4a4d26b2e78ee38c50e9d18ce55d31b00fbb9916af12e80bf3e395ff38e58f8a958427602", "hello@12345"},
#ifdef CPU_FORMAT
	{"$sspr$0$100000$NONE$1e6172e71e6af1c15f4c5ca658815835", "abc@12345"},
	{"$sspr$0$100000$NONE$1117af8ec9f70e8eed192c6c01776b6b", "abc@123"},
	{"$sspr$2$100000$4YtbuUHaTSHBuE1licTV16KjSZuMMMCn$23b3cf4e1a951b2ed9d5df43632f77092fa93128", "\xe4""bc@123"},  // original password was "äbc@123", application uses a code page
#endif
	{NULL}
};

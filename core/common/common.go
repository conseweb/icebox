package common

const (
	App_magic    = int64(87383432003452347)
	Device_magic = int64(13467864003578678)

	SharedKey_Len = 32

	Icebox_path  = "/Users/michael/.icebox/plain/"
	Secret_path  = Icebox_path + "secret.dat" // encrypted priv key
	Devid_path   = Icebox_path + "devid.dat"
	Db_path      = Icebox_path + "db.dat"
	Debug_path 	 = Icebox_path + "debug.dat"
	Session_path = Icebox_path + "session.dat" // session priv key and peer's public key

	LOCKTIME_THRESHOLD = 500000000 // 0x1DCD6500
)
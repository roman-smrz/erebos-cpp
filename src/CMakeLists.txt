include_directories(
	../include
)

add_library(erebos
	channel
	identity
	message
	network
	pubkey
	service
	state
	storage
	time
	uuid
)

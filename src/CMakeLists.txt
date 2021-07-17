include_directories(
	../include
)

add_library(erebos
	attach
	channel
	contact
	frp
	identity
	message
	network
	pairing
	pubkey
	service
	state
	storage
	sync
	time
	uuid
)

add_executable(erebos-bin
	main
)

set_target_properties(erebos-bin
	PROPERTIES OUTPUT_NAME erebos
)

target_link_libraries(erebos-bin
	erebos
	stdc++fs
	Threads::Threads
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
	${B2_LIBRARY}
	)

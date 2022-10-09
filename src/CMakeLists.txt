include_directories(
	../include
)

add_library(erebos
	attach.cpp
	channel.cpp
	contact.cpp
	frp.cpp
	identity.cpp
	message.cpp
	network.cpp
	pairing.cpp
	pubkey.cpp
	service.cpp
	set.cpp
	state.cpp
	storage.cpp
	sync.cpp
	time.cpp
	uuid.cpp
)

add_executable(erebos-bin
	main.cpp
)

set_target_properties(erebos-bin
	PROPERTIES OUTPUT_NAME erebos
)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
	target_link_libraries(erebos-bin
		erebos
		stdc++fs
		Threads::Threads
		${ZLIB_LIBRARIES}
		${OPENSSL_LIBRARIES}
		${B2_LIBRARY}
		)
endif()

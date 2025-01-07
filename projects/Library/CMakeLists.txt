project(Library VERSION 1.0.0)
add_library(Library SHARED "source/main.cpp")
target_include_directories(Library PRIVATE "source")
file(GLOB_RECURSE LINKS_JSON "links/**.link.json")
file(GLOB_RECURSE LIBRARIES "libraries/**.lib")
set(TARGET_BUILD_TYPE ${CMAKE_BUILD_TYPE})
foreach(LINK_JSON ${LINKS_JSON})
	add_custom_command(TARGET Library PRE_BUILD
		COMMAND "dynalinker" "/Input=\"${LINK_JSON}\"" "/Output=\"${CMAKE_CURRENT_SOURCE_DIR}/libraries\"" "/Version=${PROJECT_VERSION}" "/Architecture=${ARCH_NAME}" "/GenerateLib"
		COMMENT "Generating library files from ${LINK_JSON}"
	)

	add_custom_command(TARGET Library POST_BUILD
		COMMAND "dynalinker" "/Input=\"${LINK_JSON}\"" "/Output=\"${CMAKE_SOURCE_DIR}/build/${ARCH_NAME}/$<CONFIG>\"" "/Version=${PROJECT_VERSION}" "/Module=\"${CMAKE_SOURCE_DIR}/build/${ARCH_NAME}/$<CONFIG>/${PROJECT_NAME}.dll\"" "/ModulePatch"
	)
endforeach()
target_link_libraries(Library PRIVATE ${LIBRARIES})
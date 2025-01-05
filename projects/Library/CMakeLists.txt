project(Library VERSION 1.0.0)
add_library(Library SHARED "source/main.cpp")
target_include_directories(Library PRIVATE "source")
file(GLOB_RECURSE LINKS_JSON "links/**.link.json")
file(GLOB_RECURSE LIBRARIES "libraries/**.lib")
set(TARGET_BUILD_TYPE ${CMAKE_BUILD_TYPE})
foreach(LINK_JSON ${LINKS_JSON})
	add_custom_command(TARGET Library PRE_BUILD
		COMMAND "dynalinker" "-input" "${LINK_JSON}" "-output" "${CMAKE_CURRENT_SOURCE_DIR}/libraries" "-version" "${PROJECT_VERSION}" "-generatelib" "${ARCH_NAME}"
		COMMENT "Generating library files from ${LINK_JSON}"
	)

	add_custom_command(TARGET Library POST_BUILD
		COMMAND "dynalinker" "-input" "${LINK_JSON}" "-output" "${CMAKE_SOURCE_DIR}/build/${ARCH_NAME}/$<CONFIG>" "-version" "${PROJECT_VERSION}" "-modulepatch" "${CMAKE_SOURCE_DIR}/build/${ARCH_NAME}/$<CONFIG>/${PROJECT_NAME}.dll"
	)
endforeach()
target_link_libraries(Library PRIVATE ${LIBRARIES})
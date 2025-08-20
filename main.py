# Simple terminal app to list running processes and show memory usage
import os
import sys
import logging
import psutil
import shutil
from colorama import init as colorama_init, Fore, Style

# Initialize colorama for Windows terminals
colorama_init()

def list_processes():
	processes = []
	for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
		try:
			# touch basic info to avoid later AccessDenied surprises
			_ = proc.info
			processes.append(proc)
		except (psutil.NoSuchProcess, psutil.AccessDenied):
			continue
	return processes

def show_menu(processes):
	print("\nOpen Applications:")
	for idx, proc in enumerate(processes):
		name = proc.info.get('name') or '<unknown>'
		pid = proc.info.get('pid')
		try:
			cpu = proc.cpu_percent(interval=0.0)
			memp = proc.memory_percent()
			status = proc.info.get('status', '')
			print(f"{idx+1}. {name} (PID: {pid}) CPU: {cpu:.1f}% MEM: {memp:.1f}% {status}")
		except (psutil.NoSuchProcess, psutil.AccessDenied):
			print(f"{idx+1}. {name} (PID: {pid}) [access denied]")
	print("0. Back")

def kill_process(proc):
	try:
		proc.terminate()
		try:
			proc.wait(timeout=3)
			print('Process terminated.')
		except psutil.TimeoutExpired:
			proc.kill()
			print('Process killed.')
	except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
		print('Could not terminate process:', e)

def clear_screen():
	# Works on Windows; keeps consistent with earlier behavior
	os.system('cls')

NYX_ART = """
NNNNN    NNNN    YYYY   YYYY   XXX      XXX
NNNNNNN  NNNN     YYY   YYY     XXX    XXX
NNNN NN  NNNN      YYY  YYY       XXXXXX
NNNN NN  NNNN        YYY           XXXX
NNNN NN  NNNN        YYY          XXXXXX
NNNN   NNNNNN        YYY        XXX     XXX
NNNN   NNNNNN        YYY       XXX       XXX
"""

def center_text(text):
	try:
		cols = shutil.get_terminal_size().columns
	except Exception:
		cols = 80
	# Support multi-line text
	lines = text.splitlines()
	return "\n".join([line.center(cols) for line in lines])

def show_main_menu():
	print()
	# Print header in yellow
	print(Fore.YELLOW + center_text(NYX_ART) + Style.RESET_ALL)
	print()
	# Center the menu items as well
	print(Fore.YELLOW + center_text('[1] List Processes') + Style.RESET_ALL)
	print(Fore.YELLOW + center_text('[2] Read/Change memory per app') + Style.RESET_ALL)
	print(Fore.YELLOW + center_text('[3] Close') + Style.RESET_ALL)

def show_memory(proc):
	try:
		mem = proc.memory_info()
		print(f"\nProcess info for {proc.info.get('name','<unknown>')} (PID: {proc.info.get('pid')}):")
		print(f"  RSS: {mem.rss / (1024*1024):.2f} MB")
		print(f"  VMS: {mem.vms / (1024*1024):.2f} MB")
		try:
			print(f"  CPU%: {proc.cpu_percent(interval=0.1):.1f}%")
			print(f"  Threads: {proc.num_threads()}")
		except (psutil.NoSuchProcess, psutil.AccessDenied):
			pass
		try:
			files = proc.open_files()
			if files:
				print('  Open files:')
				for f in files[:5]:
					print('   -', f.path)
		except (psutil.AccessDenied, psutil.NoSuchProcess):
			pass
	except (psutil.NoSuchProcess, psutil.AccessDenied):
		print("Could not access memory info for this process.")

def change_priority(proc):
	try:
		print('\nCurrent priority: ', proc.nice())
		print('Choose new priority:')
		print('[1] Low')
		print('[2] Below Normal')
		print('[3] Normal')
		print('[4] Above Normal')
		print('[5] High')
		choice = input('Select priority (number) or Enter to cancel: ')
		if not choice:
			return
		mapping = {
			'1': psutil.IDLE_PRIORITY_CLASS if hasattr(psutil, 'IDLE_PRIORITY_CLASS') else 10,
			'2': psutil.BELOW_NORMAL_PRIORITY_CLASS if hasattr(psutil, 'BELOW_NORMAL_PRIORITY_CLASS') else 5,
			'3': psutil.NORMAL_PRIORITY_CLASS if hasattr(psutil, 'NORMAL_PRIORITY_CLASS') else 0,
			'4': psutil.ABOVE_NORMAL_PRIORITY_CLASS if hasattr(psutil, 'ABOVE_NORMAL_PRIORITY_CLASS') else -5,
			'5': psutil.HIGH_PRIORITY_CLASS if hasattr(psutil, 'HIGH_PRIORITY_CLASS') else -10,
		}
		if choice in mapping:
			proc.nice(mapping[choice])
			print('Priority changed.')
		else:
			print('Invalid choice.')
	except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
		print('Could not change priority:', e)

def main():
	while True:
		clear_screen()
		show_main_menu()
		choice = input('\nSelect an option: ')
		if choice == '1':
			# List processes with optional search and selection
			while True:
				clear_screen()
				q = input('Search processes by name (or press Enter to list all, 0 to back): ')
				if q == '0':
					break
				procs = list_processes()
				if q:
					procs = [p for p in procs if q.lower() in (p.info.get('name') or '').lower()]
				if not procs:
					print('No processes found.')
					input('\nPress Enter to continue...')
					continue
				clear_screen()
				show_menu(procs)
				try:
					sel = int(input('\nSelect a process to view (number) or 0 to back: '))
				except ValueError:
					continue
				if sel == 0:
					break
				if 1 <= sel <= len(procs):
					p = procs[sel-1]
					clear_screen()
					show_memory(p)
					print('\nActions:')
					print('[1] Kill process')
					print('[0] Back')
					a = input('Choose action: ')
					if a == '1':
						confirm = input('Type YES to confirm killing PID %s: ' % p.pid)
						if confirm == 'YES':
							kill_process(p)
							input('\nPress Enter to continue...')
						else:
							print('Cancelled.')
							input('\nPress Enter to continue...')
					else:
						input('\nPress Enter to continue...')
				else:
					continue
		elif choice == '2':
			# Read/Change memory per app (safe: read memory info and allow changing priority)
			while True:
				clear_screen()
				procs = list_processes()
				show_menu(procs)
				try:
					sel = int(input('\nSelect an app to view/change (number, 0 to go back): '))
				except ValueError:
					print('Invalid input.')
					input('\nPress Enter to continue...')
					continue
				if sel == 0:
					break
				if 1 <= sel <= len(procs):
					clear_screen()
					p = procs[sel-1]
					show_memory(p)
					print('\nActions:')
					print('[1] Change priority (safe)')
					print('[2] Attempt to write arbitrary memory (NOT SUPPORTED)')
					print('[0] Back')
					act = input('Choose action: ')
					if act == '1':
						change_priority(p)
						input('\nPress Enter to continue...')
					elif act == '2':
						print('\nWriting arbitrary process memory is unsafe and not supported by this tool.')
						print('If you meant to change process behavior, consider changing priority or restarting it with different args.')
						input('\nPress Enter to continue...')
					else:
						continue
				else:
					print('Invalid choice.')
					input('\nPress Enter to continue...')
		elif choice == '3':
			print('Closing.')
			break
		else:
			print('Invalid selection.')
			input('\nPress Enter to continue...')

if __name__ == "__main__":
	main()


#!/usr/bin/osascript
# 20210713
# 根据屏幕亮度自动设置外观模式，只支持Mojave以后的版本
# 运行方式终端运行 osascript auto_swap_dark_mode.scpt

# 查看当前外观是否为Dark模式,是则返回true
on current_dark_mode()
	tell application "System Events"
		tell appearance preferences
			get dark mode
		end tell
	end tell
end current_dark_mode

# 获取当前的屏幕亮度值（只输出主显示器）
# 依赖brightness工具
set current_screen to do shell script "/usr/local/bin/brightness -l 2>&1 |grep 'display 0: brightness' |awk '{print $NF}'"

(*
	1、根据当前的屏幕亮度值进行判断
	2、如果当前亮度值小于70%，且当前外观模式不是Dark则将当前外观设置为Dark模式
	3、如果当前亮度值大于70%，且当前外观模式为Dark则将当前外观设置为Light
*)
if current_screen < 0.7 and not current_dark_mode() then
	# say "将外观模式设置为Dark"
	tell application "System Events"
		tell appearance preferences
			set dark mode to true
		end tell
	end tell
end if

if current_screen > 0.7 and current_dark_mode() then
	# say "将外观模式设置为Light"
	tell application "System Events"
		tell appearance preferences
			set dark mode to false
		end tell
	end tell
end if

# 打印当前屏幕亮度值
do shell script "echo 当前屏幕亮度值为 " & current_screen

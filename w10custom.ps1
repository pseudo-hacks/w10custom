<#
    w10custom
    Copyright (C) 2016 pseudo-hacks.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#>

$DebugPreference = "SilentlyContinue"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

<# variables #>

$software_name = "w10custom"

$folder_options = @(
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       ;name = 'HideFileExt'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '登録されている拡張子も表示する'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       ;name = 'LaunchTo'
       ;value = 1
       ;default_value = 2
       ;type = 'DWord'
       ;text = 'エクスプローラでクイックアクセスではなくPCを開く'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
       ;name = 'FullPath'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'タイトルバーに完全なパスを表示する'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
       ;name = 'ShowRecent'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '最近使ったファイルをクイックアクセスに表示しない'
       ;recommend = $false
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
       ;name = 'ShowFrequent'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'よく使うフォルダーをクイックアクセスに表示しない'
       ;recommend = $false
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       ;name = 'NavPaneShowAllFolders'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'ナビゲーションウィンドウにすべてのフォルダーを表示する'
       ;recommend = $false
       ;performance = $false
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
       ;name = 'NavPaneExpandToCurrentFolder'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'ナビゲーションウィンドウで開いているフォルダまで展開する'
       ;recommend = $false
       ;performance = $false
       ;admin = $false
    }
)

$network_options = @(
     @{ path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting'
       ;name = 'value'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'Wi-Fiセンサー（ホットスポット共有）を許可しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots'
       ;name = 'value'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '共有されたホットスポットへの自動接続を許可しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
)

$appearance_options = @(
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
       ;name = 'SystemPaneSuggestionsEnabled'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'スタート画面におすすめ（広告）を表示しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\Control Panel\Desktop\WindowMetrics'
       ;name = 'MinAnimate'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'ウィンドウの最大化、最小化時にアニメーションを表示しない'
       ;recommend = $false
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
       ;name = 'EnableTransparency'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'スタート、タスク バー、アクション センターを透明にしない'
       ;recommend = $false
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
       ;name = 'ColorPrevalence'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'スタート、タスク バー、アクション センター、タイトル バーに色をつける'
       ;recommend = $false
       ;performance = $false
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
       ;name = 'AppsUseLightTheme'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'ダークテーマを使用する'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC'
       ;name = 'EnableMtcUvc'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'ボリュームミキサーをWindows 8.1以前と同じものに変える'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
       ;name = 'NoLockScreen'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'ロックスクリーンを無効化する'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
)

$windows_update_options = @(
     @{ path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
       ;name = 'UxOption'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = '更新プログラムのインストール時に再起動の日時を設定するよう通知する'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
       ;name = 'NoAutoRebootWithLoggedOnUsers'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = '更新プログラムのインストール時に自動的に再起動しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
       ;name = 'DODownloadMode'
       ;value = 1
       ;default_value = 3
       ;type = 'DWord'
       ;text = '更新プログラムをインターネット上のPCと共有しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
       ;additional_items = @(
            ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization'
               ;name = 'SystemSettingsDownloadMode'
               ;value = 3
               ;default_value = 1
               ;type = 'DWord'
            }
       )
    }
)

$privacy_options = @(
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
       ;name = 'Enabled'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '広告IDを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
       ;name = 'EnableWebContentEvaluation'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'WindowsストアアプリのSmartScreenフィルター機能を無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter'
       ;name = 'EnabledV9'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'Internet ExplorerのSmartScreenフィルター機能を無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter'
       ;name = 'EnabledV9'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'Microsoft EdgeのSmartScreenフィルター機能を無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Input\TIPC'
       ;name = 'Enabled'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '入力に関する情報をマイクロソフトに送信しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
       ;name = 'BingSearchEnabled'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'タスクバー検索にWebの検索結果を含めない'
       ;recommend = $true
       ;performance = $true
       ;admin = $false
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
       ;name = 'DisableWebSearch'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'WindowsサーチからWeb検索オプションを削除する'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
       ;name = 'ConnectedSearchUseWeb'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'WindowsサーチでWeb検索を行わない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
       ;name = 'AllowCortana'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = '音声アシスタントCortanaの実行を許可しない'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
       ;additional_items = @(
            ,@{ path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana'
               ;name = 'value'
               ;value = 0
               ;default_value = 1
               ;type = 'DWord'
            }
       )
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
       ;name = 'CEIPEnable'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'Windowsカスタマーエクスペリエンス向上プログラムを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
       ;name = 'AllowTelemetry'
       ;value = 0
       ;default_value = 3
       ;type = 'DWord'
       ;text = 'デバイスのデータの送信を抑制する'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
       ;name = 'AITEnable'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'アプリケーション影響度遠隔測定エージェントを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat'
       ;name = 'DisableUAR'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = '問題ステップ記録ツールをオフにする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
<#
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
       ;name = 'EnabledV9'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'Microsoft EdgeのSmartScreenフィルター機能を無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
#>
    ,@{ service_name = 'DiagTrack'
       ;text = '診断追跡サービスを無効化する'
       ;default = 'Auto'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'dmwappushservice'
       ;text = 'WAPプッシュメッセージルーティングサービスを無効化する'
       ;default = 'Manual'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
       ;name = 'Status'
       ;value = 0
       ;default_value = 1
       ;type = 'DWord'
       ;text = 'デバイスの位置情報をオフにする'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
    ,@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
       ;name = 'DisableFileSyncNGSC'
       ;value = 1
       ;default_value = 0
       ;type = 'DWord'
       ;text = 'OneDriveをファイル記憶域として使用できないようにする'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
)

$service_options = @(
    ,@{ service_name = 'DPS'
       ;text = '診断ポリシーサービスを無効にする'
       ;default = 'Auto'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'TrkWks'
       ;text = 'Distributed Link Tracking Clientサービスを無効にする'
       ;default = 'Auto'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'PcaSvc'
       ;text = 'プログラム互換性アシスタントサービスを無効にする'
       ;default = 'Auto'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'seclogon'
       ;text = 'Secondary Logonサービスを無効にする'
       ;default = 'Manual'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'WerSvc'
       ;text = 'Windowsエラー報告サービスを無効にする'
       ;default = 'Manual'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ service_name = 'iphlpsvc'
       ;text = 'IP Helperサービスを無効にする'
       ;default = 'Auto'
       ;recommend = $false
       ;performance = $false
       ;admin = $true
    }
)

$task_options = @(
    ,@{ tasks = @(
                    ,@{  path = '\Microsoft\Windows\Application Experience'
                        ;name = 'Microsoft Compatibility Appraiser'
                    }
                    ,@{  path = '\Microsoft\Windows\Application Experience'
                        ;name = 'ProgramDataUpdater'
                    }
                    ,@{  path = '\Microsoft\Windows\Autochk'
                        ;name = 'Proxy'
                    }
                    ,@{  path = '\Microsoft\Windows\Customer Experience Improvement Program'
                        ;name = 'Consolidator'
                    }
                    ,@{  path = '\Microsoft\Windows\Customer Experience Improvement Program'
                        ;name = 'KernelCeipTask'
                    }
                    ,@{  path = '\Microsoft\Windows\Customer Experience Improvement Program'
                        ;name = 'UsbCeip'
                    }
                    ,@{  path = '\Microsoft\Windows\DiskDiagnostic'
                        ;name = 'Microsoft-Windows-DiskDiagnosticDataCollector'
                    }
                )
       ;text = 'カスタマーエクスペリエンス向上プログラム関連データ送信タスクを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ tasks = @(
                    ,@{  path = '\Microsoft\Windows\Power Efficiency Diagnostics'
                        ;name = 'AnalyzeSystem'
                    }
                )
       ;text = '電源管理の分析タスクを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ tasks = @(
                    ,@{  path = '\Microsoft\Windows\Defrag'
                        ;name = 'ScheduledDefrag'
                    }
                )
       ;text = '自動デフラグタスクを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ tasks = @(
                    ,@{  path = '\Microsoft\Windows\Maintenance'
                        ;name = 'WinSAT'
                    }
                )
       ;text = 'システム性能測定タスクを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
    ,@{ tasks = @(
                    ,@{  path = '\Microsoft\Windows\Windows Error Reporting'
                        ;name = 'QueueReporting'
                    }
                )
       ;text = 'Windowsエラー報告タスクを無効にする'
       ;recommend = $true
       ;performance = $true
       ;admin = $true
    }
)

$service_names = @()
foreach ( $item in ($privacy_options + $service_options) ) {
    if ( $item.ContainsKey('service_name') ) {
        $service_names += $item['service_name']
    }
}

<# registry functions #>

function Test-RegistryValue($path, $name) {
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($key) {
        if ( $null -ne $key.GetValue($name, $null) ) {
            return $true
        } else {
            return $false
        }
    }
    return $false
}

function Get-RegistryValue($path, $name) {
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($key) {
        return $key.GetValue($name, $null)
    } else {
        return $null
    }
}

function Set-RegistryValue($path, $name, $value, $type = "DWord") {
    If (-Not (Test-Path $path)) {
    	New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name $name -Type $type -Value $value -Force | Out-Null
    Write-Debug ("Set-RegistryValue {0} {1} {2} {3}" -f $path, $name, $value, $type)
}

<# form functions #>

function disclaimer {
    $text = "このソフトウェアは、GNU General Public Licenseバージョン3 (GPLv3)のもと提供されています。`n" +
            "このソフトウェアは無保証であり、どのようなトラブルが発生しても著作権者は責任を負わないものとします。`n" +
            "このソフトウェアの著作権やライセンスについての詳細は、起動後に「About」タブを参照してください。" +
            "`n`n" +
            "このソフトウェアは、個人利用のWindows 10 PCを対象としています。組織の管理下にあるPCでは、想定通りに動作しない可能性があります。"
    $caption = "確認 - " + $software_name
    $buttonsType = "OKCancel"
    $iconType = "Question"
    $result = [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttonsType, $iconType)
    if ( $result -ne 'OK' ) {
        exit
    }
}

$script:admin = $true
function check_admin {
    if ( ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $false ) {
        $text = "標準ユーザーとして実行されています。管理者ユーザーとして実行しない場合、一部の設定を行うことができません。"
        $caption = "確認 - " + $software_name
        $buttons = "OKCancel"
        $icon = "Information"
        $default_button = "Button1"
        [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttons, $icon, $default_button) | Out-Null
        $script:admin = $false
    }
}

function customize_form {
    function set_item ( $items, $CheckedList ) {
        foreach ( $item in $items ) {
            $i = $items.IndexOf($item)
            if ( ($script:admin -eq $false) -and ($item['admin'] -eq $true) ) {
                $CheckedList.Items.Insert($i, $item['text'])
                $CheckedList.SetItemCheckState($i, [System.Windows.Forms.CheckState]::Indeterminate)
            } else {
	            if ( $item.ContainsKey('path') ) {
	                $CheckedList.Items.Insert($i, $item['text'])
	                $item['current_value'] = Get-RegistryValue $item['path'] $item['name']
	                if ( $item['value'] -eq $item['current_value'] ) {
	                    $CheckedList.SetItemChecked($i, $true)
                    }
	                if ( $item.ContainsKey('additional_items') ) {
	                    foreach ( $aitem in $item['additional_items'] ) {
	                        $aitem['current_value'] = Get-RegistryValue $aitem['path'] $aitem['name']
	                        if ( $aitem['value'] -ne $aitem['current_value'] ) {
	                            $CheckedList.SetItemChecked($i, $false)
	                        }
	                    }
	                }
	            } elseif ( $item.ContainsKey('service_name') ) {
	                $CheckedList.Items.Insert($i, $item['text'])
	                if ( $script:admin -eq $true ) {
	                    $service_name = $item['service_name']
	                    if ( $services.ContainsKey($service_name) ) {
	                        if ( $services[$service_name]['StartMode'] -eq 'Disabled' ) {
	                            $CheckedList.SetItemChecked($i, $true)
	                        }
	                    } else {
	                        $CheckedList.SetItemCheckState($i, [System.Windows.Forms.CheckState]::Indeterminate)
	                    }
	                }
	            } elseif ( $item.ContainsKey('tasks') ) {
	                $CheckedList.Items.Insert($i, $item['text'])
	                if ( $script:admin -eq $true ) {
	                    $CheckedList.SetItemChecked($i, $true)
	                    foreach ( $task in $item['tasks'] ) {
	                        foreach ( $system_task in $system_tasks ) {
	                            if ( ($task.path -eq $system_task.TaskPath) -and 
	                                 ($task.name -eq $system_task.TaskName) ) {
	                                if ( ($system_task.State -eq 'Ready') -or ($system_task.State -eq 'Running') ) {
	                                    $CheckedList.SetItemChecked($i, $false)
	                                }
	                                break
	                            }
	                        }
	                    }
	                }
	            }
	        }
		}
    }

    function apply {
        <# apply checkedlistboxes #>
        foreach ( $items in
                    @(
                        ,@{ options = $folder_options;         checked_list = $FolderOptionsCheckedList }
                        ,@{ options = $network_options;        checked_list = $NetworkCheckedList }
                        ,@{ options = $appearance_options;     checked_list = $AppearanceCheckedList }
                        ,@{ options = $windows_update_options; checked_list = $WindowsUpdateCheckedList }
                        ,@{ options = $privacy_options;        checked_list = $PrivacyCheckedList }
                        ,@{ options = $service_options;        checked_list = $ServiceCheckedList }
                        ,@{ options = $task_options;           checked_list = $TaskCheckedList }
                    )
                ) {
            foreach ( $item in $items['options'] ) {
                if ( ($item['admin'] -eq $false) -or ($script:admin -eq $true) ) {
                    $i = $items['options'].IndexOf($item)
	                if ( $item.ContainsKey('path') ) {
	                    if ( $items['checked_list'].GetItemChecked($i) ) {
                            if ( $item['current_value'] -ne $item['value'] ) {
                                # チェックオン&現在値がチェックオン時の値と異なる場合
                                Set-RegistryValue $item['path'] $item['name'] $item['value'] $item['type']
                            }
	                    } else {
                            if ( $item['current_value'] -eq $item['value'] ) {
                                # チェックオフ&現在値がチェックオン時の値の場合
	                            Set-RegistryValue $item['path'] $item['name'] $item['default_value'] $item['type']
                            }
	                    }
	                    if ( $item -contains 'additional_items' ) {
	                        foreach ( $aitem in $item['additional_items'] ) {
    	                        if ( $items['checked_list'].GetItemChecked($i) ) {
                                    if ( $aitem['current_value'] -ne $aitem['value'] ) {
                                        # チェックオン&現在値がチェックオン時の値と異なる場合
                                        Set-RegistryValue $aitem['path'] $aitem['name'] $aitem['value'] $aitem['type']
                                    }
	                            } else {
                                    if ( $aitem['current_value'] -eq $aitem['value'] ) {
                                        # チェックオフ&現在値がチェックオン時の値の場合
	                                    Set-RegistryValue $aitem['path'] $aitem['name'] $aitem['default_value'] $aitem['type']
                                    }
	                            }
	                        }
	                    }
	                } elseif ( $item.ContainsKey('service_name') ) {
	                    $service_name = $item['service_name']
	                    if ( $services.ContainsKey($service_name) ) {
	                        if ( $items['checked_list'].GetItemChecked($i) ) {
	                          if ( $services[$service_name]['StartMode'] -ne 'Disabled' ) {
	                              Stop-Service $service_name -Force
	                              Set-Service $service_name -StartupType Disabled
                                  Write-Debug ("Set-Service {0} -StartupType Disabled" -f $service_name)
	                          }
	                        } else {
	                          if ( $services[$service_name]['StartMode'] -eq 'Disabled' ) {
	                              Set-Service $service_name -StartupType $item['default']
                                  Write-Debug ("Set-Service {0} -StartupType {1}" -f $service_name, $item['default'])
	                          }
	                        }
	                    }
	                } elseif ( $item.ContainsKey('tasks') ) {
                        # TODO: 無変更なら設定をしない
	                    if ( $items['checked_list'].GetItemChecked($i) ) {
                            foreach ( $task in $item['tasks'] ) {
                                Disable-ScheduledTask -TaskPath $task['path'] -TaskName $task['name']
                                Write-Debug ("Disable-ScheduledTask -TaskPath {0} -TaskName {1}" -f $task['path'], $task['name'])
                            }
                        } else {
                            foreach ( $task in $item['tasks'] ) {
                                Enable-ScheduledTask -TaskPath $task['path'] -TaskName $task['name']
                                Write-Debug ("Enable-ScheduledTask -TaskPath {0} -TaskName {1}" -f $task['path'], $task['name'])
                            }
                        }
	                } else {
	                    Write-Debug ("Unknown option type: " + $item['text'])
	                }
	            }
            }
        }

        <# apply capslock #>
        if ( $script:admin -eq $true ) {
            # TODO: 無変更なら設定をしない
            if ( $CapsCtrlRadioButton.Checked -eq $true ) {
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" "Scancode Map" $caps_to_ctrl_map "Binary"
            } elseif ( $CapsSwapRadioButton.Checked -eq $true ) {
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" "Scancode Map" $swap_caps_ctrl_map "Binary"
            }
        }
    }

    function recommend_setting {
        foreach ( $items in
                    @(
                        ,@{ options = $folder_options;         checked_list = $FolderOptionsCheckedList }
                        ,@{ options = $network_options;        checked_list = $NetworkCheckedList }
                        ,@{ options = $appearance_options;     checked_list = $AppearanceCheckedList }
                        ,@{ options = $windows_update_options; checked_list = $WindowsUpdateCheckedList }
                        ,@{ options = $privacy_options;        checked_list = $PrivacyCheckedList }
                        ,@{ options = $service_options;        checked_list = $ServiceCheckedList }
                        ,@{ options = $task_options;           checked_list = $TaskCheckedList }
                    )
                ) {
            foreach ( $item in $items['options'] ) {
                if ( ($item['admin'] -eq $true) -and ($script:admin -eq $false) ) {
                    continue
                }
                $i = $items['options'].IndexOf($item)
                if ( $item['recommend'] -eq $true ) {
                    if ( $items['checked_list'].GetItemChecked($i) -eq $false ) {
                        Write-Host ("{0} をオンにします" -f $item['text'])
                        $items['checked_list'].SetItemChecked($i, $true)
                    }
                } else {
                    if ( $items['checked_list'].GetItemChecked($i) -eq $true ) {
                        Write-Host ("{0} をオフにします" -f $item['text'])
                        $items['checked_list'].SetItemChecked($i, $false)
                    }
                }
            }
        }
    }

    function performance_setting {
        foreach ( $items in
                    @(
                        ,@{ options = $folder_options;         checked_list = $FolderOptionsCheckedList }
                        ,@{ options = $network_options;        checked_list = $NetworkCheckedList }
                        ,@{ options = $appearance_options;     checked_list = $AppearanceCheckedList }
                        ,@{ options = $windows_update_options; checked_list = $WindowsUpdateCheckedList }
                        ,@{ options = $privacy_options;        checked_list = $PrivacyCheckedList }
                        ,@{ options = $service_options;        checked_list = $ServiceCheckedList }
                        ,@{ options = $task_options;           checked_list = $TaskCheckedList }
                    )
                ) {
            foreach ( $item in $items['options'] ) {
                if ( ($item['admin'] -eq $true) -and ($script:admin -eq $false) ) {
                    continue
                }
                $i = $items['options'].IndexOf($item)
                if ( $item['performance'] -eq $true ) {
                    if ( $items['checked_list'].GetItemChecked($i) -eq $false ) {
                        Write-Host ("{0} をオンにします" -f $item['text'])
                        $items['checked_list'].SetItemChecked($i, $true)
                    }
                } else {
                    if ( $items['checked_list'].GetItemChecked($i) -eq $true ) {
                        Write-Host ("{0} をオフにします" -f $item['text'])
                        $items['checked_list'].SetItemChecked($i, $false)
                    }
                }
            }
        }
    }

    # サービスの状態
    $services = @{}
    if ( $script:admin -eq $true ) {
        $filter = ''
        foreach ( $service_name in $service_names ) {
           if ( $filter.Length -gt 0 ) {
                $filter += ' OR '
            }
            $filter += "NAME='$service_name'"
        }
        foreach ( $service in (Get-WmiObject Win32_Service -filter $filter ) ) {
            $services[$service.Name] += @{ StartMode = $service.StartMode; State = $service.State }
        }
    }

    # タスクの状態
    $system_tasks = @()
    if ( $script:admin -eq $true ) {
        $system_tasks = Get-ScheduledTask
    }

    $Form = New-Object System.Windows.Forms.Form    
    $Form.Size = New-Object System.Drawing.Size(1, 1) 
    $Form.AutoSize = $true 
    $Form.FormBorderStyle = "FixedSingle";
    $Form.MaximizeBox = $false
    $Form.text = $software_name

    $TabControl = New-object System.Windows.Forms.TabControl
    $TabControl.Multiline = $True
    $TabControl.Location = New-Object System.Drawing.Point(3, 3)
    $TabControl.Size = New-Object System.Drawing.Size(460, 464)
    $Form.Controls.Add($TabControl)

    $MainPage = New-Object System.Windows.Forms.TabPage
    $MainPage.UseVisualStyleBackColor = $True
    $MainPage.Text = "簡単設定"

    $FolderOptionsPage = New-Object System.Windows.Forms.TabPage
    $FolderOptionsPage.UseVisualStyleBackColor = $True
    $FolderOptionsPage.Text = "フォルダーオプション"

    $NetworkPage = New-Object System.Windows.Forms.TabPage
    $NetworkPage.UseVisualStyleBackColor = $True
    $NetworkPage.Text = "ネットワーク"

    $AppearancePage = New-Object System.Windows.Forms.TabPage
    $AppearancePage.UseVisualStyleBackColor = $True
    $AppearancePage.Text = "外観"

    $WindowsUpdatePage = New-Object System.Windows.Forms.TabPage
    $WindowsUpdatePage.UseVisualStyleBackColor = $True
    $WindowsUpdatePage.Text = "Windows Update"

    $PrivacyPage = New-Object System.Windows.Forms.TabPage
    $PrivacyPage.UseVisualStyleBackColor = $True
    $PrivacyPage.Text = "プライバシー"

    $ServicePage = New-Object System.Windows.Forms.TabPage
    $ServicePage.UseVisualStyleBackColor = $True
    $ServicePage.Text = "サービス"

    $TaskPage = New-Object System.Windows.Forms.TabPage
    $TaskPage.UseVisualStyleBackColor = $True
    $TaskPage.Text = "タスク"

    $CapsLockPage = New-Object System.Windows.Forms.TabPage
    $CapsLockPage.UseVisualStyleBackColor = $True
    $CapsLockPage.Text = "CapsLock"

    $AboutPage = New-Object System.Windows.Forms.TabPage
    $AboutPage.UseVisualStyleBackColor = $True
    $AboutPage.Text = "About"

    $TabControl.Controls.AddRange(@($MainPage, 
                                    $FolderOptionsPage, 
                                    $NetworkPage, 
                                    $CapsLockPage, 
                                    $AppearancePage, 
                                    $WindowsUpdatePage, 
                                    $PrivacyPage, 
                                    $ServicePage, 
                                    $TaskPage, 
                                    $AboutPage))
    
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(280, 470)
    $OKButton.Size = New-Object System.Drawing.Size(86, 24)
    $OKButton.Text = "OK"
    $OKButton.Add_Click(
        {
            $text = "項目により、再起動後に反映されるものがあります。"
            $caption = "確認 - " + $software_name
            $buttonsType = "OKCancel"
            $iconType = "Question"
            $result = [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttonsType, $iconType)
            if ( $result -eq 'OK' ) {
                apply
                $Form.Close()
            }
        }
    )
    $Form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(376, 470)
    $CancelButton.Size = New-Object System.Drawing.Size(86, 24)
    $CancelButton.Text = "キャンセル"
    $CancelButton.Add_Click(
        {
            $text = "変更した設定は破棄されます。`n終了してよろしいですか？"
            $caption = "確認 - " + $software_name
            $buttonsType = "OKCancel"
            $iconType = "Question"
            $result = [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttonsType, $iconType)
            if ( $result -eq 'OK' ) {
                $Form.Close()
            }
        }
    )
    $Form.Controls.Add($CancelButton)

    <# About #>
    $AppNameLabel = New-Object System.Windows.Forms.Label
    $AppNameLabel.Location = '150, 20'
    $AppNameLabel.Size = '260, 24'
  	$AppNameLabel.Text = $software_name
    $AppNameLabel.Font = New-Object System.Drawing.Font("Courier New", 16, [System.Drawing.FontStyle]::Bold)
    $AboutPage.Controls.Add($AppNameLabel)

    $CopyrightLabel = New-Object System.Windows.Forms.Label
    $CopyrightLabel.Location = '70, 50'
    $CopyrightLabel.Size = '400, 24'
  	$CopyrightLabel.Text = 'Copyright © 2016 pseudo-hacks.com All Rights Reserved.'
    $AboutPage.Controls.Add($CopyrightLabel)

    $LicenseTextBox = New-Object System.Windows.Forms.TextBox
    $LicenseTextBox.Location = '8, 90'
    $LicenseTextBox.Size = '435, 300'
    $LicenseTextBox.Multiline = $true
    $LicenseTextBox.Text = "This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>."
    $LicenseTextBox.ReadOnly = $true
    $AboutPage.Controls.Add($LicenseTextBox)

    <# CapsLock #>
    $caps_to_ctrl_map = ([byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0,
                         [byte]2, [byte]0, [byte]0, [byte]0, [byte]29, [byte]0, [byte]58, [byte]0,
                         [byte]0, [byte]0, [byte]0, [byte]0);
	$swap_caps_ctrl_map = ([byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0,
                           [byte]3, [byte]0, [byte]0, [byte]0, [byte]29, [byte]0, [byte]58, [byte]0,
                           [byte]58, [byte]0, [byte]29, [byte]0, [byte]0, [byte]0, [byte]0, [byte]0);
	$current_map = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" "Scancode Map"
    
    $caps_ctrl = $caps_swap = $caps_default = $caps_custom = $false
    if ( ($current_map) -and ([system.String]::Join(" ", $caps_to_ctrl_map) -eq [system.String]::Join(" ", $current_map)) ) {
        $caps_ctrl = $true;
    } elseif ( ($current_map) -and ([system.String]::Join(" ", $swap_caps_ctrl_map) -eq [system.String]::Join(" ", $current_map)) ) {
        $caps_swap = $true;
    } else {
        if ( $current_map ) {
            $caps_custom = $true;
        }
        $caps_default = $true;
    }

    $CapsLockGroupBox = New-Object System.Windows.Forms.GroupBox
    $CapsLockGroupBox.location = New-Object System.Drawing.Point(8, 8)
    $CapsLockGroupBox.size = New-Object System.Drawing.Size(435, 360)
    $CapsLockPage.Controls.Add($CapsLockGroupBox)

    $CapsCtrlRadioButton = New-Object System.Windows.Forms.RadioButton
    $CapsCtrlRadioButton.Location = '20, 40'
    $CapsCtrlRadioButton.size = '350, 20'
    $CapsCtrlRadioButton.Checked = $caps_ctrl
    $CapsCtrlRadioButton.Text = "CapsLockをCtrlに変更する"
 
    $CapsSwapRadioButton = New-Object System.Windows.Forms.RadioButton
    $CapsSwapRadioButton.Location = '20, 70'
    $CapsSwapRadioButton.size = '350, 20'
    $CapsSwapRadioButton.Checked = $caps_swap
    $CapsSwapRadioButton.Text = "CapsLockとCtrlを入れ替える"

    $CapsDefaultRadioButton = New-Object System.Windows.Forms.RadioButton
    $CapsDefaultRadioButton.Location = '20, 100'
    $CapsDefaultRadioButton.size = '350, 20'
    $CapsDefaultRadioButton.Checked = $caps_default
    $CapsDefaultRadioButton.Text = "キーマップを変更しない"

    $CapsLockGroupBox.Controls.AddRange(@($CapsCtrlRadioButton, $CapsSwapRadioButton, $CapsDefaultRadioButton))

    if ( $script:admin -eq $false ) {
        $CapsCautionLabel = New-Object System.Windows.Forms.Label
	    $CapsCautionLabel.Location = '20, 130'
	    $CapsCautionLabel.Size = '350, 40'
    	$CapsCautionLabel.Text = "設定を変更するためには、管理者として実行する必要があります。"
        $CapsLockGroupBox.Controls.Add($CapsCautionLabel)
        $CapsCtrlRadioButton.Enabled = $false
        $CapsSwapRadioButton.Enabled = $false
        $CapsDefaultRadioButton.Enabled = $false
    } elseif ( $caps_custom -eq $true ) {
        $CapsCautionLabel = New-Object System.Windows.Forms.Label
	    $CapsCautionLabel.Location = '20, 130'
	    $CapsCautionLabel.Size = '350, 40'
        $CapsCautionLabel.ForeColor = 'Red'
    	$CapsCautionLabel.Text = "Scancode Mapがカスタマイズされています。`n変更すると、カスタマイズ内容が上書きされます。"
        $CapsLockGroupBox.Controls.Add($CapsCautionLabel)
    }

    <# 簡単設定 #>
    $RecommendButton = New-Object System.Windows.Forms.Button
    $RecommendButton.Location = New-Object System.Drawing.Point(100, 30)
    $RecommendButton.Size = New-Object System.Drawing.Size(260, 24)
    $RecommendButton.Text = "おすすめ設定(&R)"
    $RecommendButton.Add_Click(
        {
            recommend_setting
            $text = "各タブの各項目を、おすすめの設定になるよう変更しました。"
            $caption = "確認 - " + $software_name
            $buttonsType = "OK"
            $iconType = "Information"
            [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttonsType, $iconType)
        }
    )
    $MainPage.Controls.Add($RecommendButton)

    $RecommendLabel = New-Object System.Windows.Forms.Label
	$RecommendLabel.Location = New-Object System.Drawing.Point(100, 60)
	$RecommendLabel.Size = New-Object System.Drawing.Size(260, 48)
	$RecommendLabel.Text = "各タブの項目を、おすすめの設定に変更します。"
    $MainPage.Controls.Add($RecommendLabel)

    $PerformanceButton = New-Object System.Windows.Forms.Button
    $PerformanceButton.Location = New-Object System.Drawing.Point(100, 120)
    $PerformanceButton.Size = New-Object System.Drawing.Size(260, 24)
    $PerformanceButton.Text = "パフォーマンス重視設定(&P)"
    $PerformanceButton.Add_Click(
        {
            performance_setting
            $text = "各タブの各項目を、パフォーマンス重視の設定になるよう変更しました。"
            $caption = "確認 - " + $software_name
            $buttonsType = "OK"
            $iconType = "Information"
            [System.Windows.Forms.MessageBox]::Show($text, $caption, $buttonsType, $iconType)
        }
    )
    $MainPage.Controls.Add($PerformanceButton)

    $PerformanceLabel = New-Object System.Windows.Forms.Label
	$PerformanceLabel.Location = New-Object System.Drawing.Point(90, 150)
	$PerformanceLabel.Size = New-Object System.Drawing.Size(300, 48)
	$PerformanceLabel.Text = "各タブの項目を、パフォーマンス重視の設定に変更します。"
    $MainPage.Controls.Add($PerformanceLabel)

    <# フォルダーオプション #>
    $FolderOptionsCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $FolderOptionsCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $FolderOptionsCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $FolderOptionsCheckedList.CheckOnClick = $true
    $FolderOptionsCheckedList.SelectionMode = "One"
    $FolderOptionsCheckedList.Update()
    $FolderOptionsCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $FolderOptionsPage.Controls.Add($FolderOptionsCheckedList)
    set_item $folder_options $FolderOptionsCheckedList

    <# ネットワーク #>
    $NetworkCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $NetworkCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $NetworkCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $NetworkCheckedList.CheckOnClick = $true
    $NetworkCheckedList.SelectionMode = "One"
    $NetworkCheckedList.Update()
    $NetworkCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $NetworkPage.Controls.Add($NetworkCheckedList)
    set_item $network_options $NetworkCheckedList

    <# 外観 #>
    $AppearanceCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $AppearanceCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $AppearanceCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $AppearanceCheckedList.CheckOnClick = $true
    $AppearanceCheckedList.SelectionMode = "One"
    $AppearanceCheckedList.Update()
    $AppearanceCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $AppearancePage.Controls.Add($AppearanceCheckedList)
    set_item $appearance_options $AppearanceCheckedList

    <# Windows Update #>
    $WindowsUpdateCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $WindowsUpdateCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $WindowsUpdateCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $WindowsUpdateCheckedList.CheckOnClick = $true
    $WindowsUpdateCheckedList.SelectionMode = "One"
    $WindowsUpdateCheckedList.Update()
    $WindowsUpdateCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $WindowsUpdatePage.Controls.Add($WindowsUpdateCheckedList)
    set_item $windows_update_options $WindowsUpdateCheckedList

    <# プライバシー #>
    $PrivacyCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $PrivacyCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $PrivacyCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $PrivacyCheckedList.CheckOnClick = $true
    $PrivacyCheckedList.SelectionMode = "One"
    $PrivacyCheckedList.Update()
    $PrivacyCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $PrivacyPage.Controls.Add($PrivacyCheckedList)
    set_item $privacy_options $PrivacyCheckedList

    <# サービス #>
    $ServiceCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $ServiceCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $ServiceCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $ServiceCheckedList.CheckOnClick = $true
    $ServiceCheckedList.SelectionMode = "One"
    $ServiceCheckedList.Update()
    $ServiceCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $ServicePage.Controls.Add($ServiceCheckedList)
    set_item $service_options $ServiceCheckedList

    <# タスク #>
    $TaskCheckedList = New-Object System.Windows.Forms.CheckedListBox
    $TaskCheckedList.location = New-Object System.Drawing.Point(8, 8)
    $TaskCheckedList.size = New-Object System.Drawing.Size(435, 360)
    $TaskCheckedList.CheckOnClick = $true
    $TaskCheckedList.SelectionMode = "One"
    $TaskCheckedList.Update()
    $TaskCheckedList.Add_ItemCheck(
        {
            param($s, $e)
            if ( $e.CurrentValue -eq [System.Windows.Forms.CheckState]::Indeterminate ) {
                $e.NewValue = [System.Windows.Forms.CheckState]::Indeterminate
            }
        }
    )
    $TaskPage.Controls.Add($TaskCheckedList)
    set_item $task_options $TaskCheckedList

    $Form.ShowDialog() | Out-Null
}

<# Main Routine #>

disclaimer
check_admin
customize_form
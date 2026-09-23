# pam_watchid

[English](README.md) | [日本語](README.ja.md)

Macの `sudo` を **Apple WatchまたはTouch ID** で承認できます。どちらも利用できない場合、
キャンセルした場合、タイムアウトした場合は、通常のパスワード入力など、既存のsudo認証に戻ります。

**リリース状況：** [0.1.1](https://github.com/rioriost/pam_watchid/releases/tag/v0.1.1)
は初回の**プレリリース**です。Golden Gate 27搭載のApple Silicon Mac 1台で、
Apple Watch、Touch ID、キャンセル、パスワードへの切り替えを確認しました。
ほかのハードウェア・OSや追加のセッション条件は未確認であり、
すべての対応対象で安定動作を確認したリリースではありません。

## 対応環境

| macOS | Apple Silicon | Intel |
| --- | --- | --- |
| Sequoia 15 | 対応対象 | 対応対象 |
| Tahoe 26 | 対応対象 | 対応対象 |
| Golden Gate 27 | 実機確認あり（1台） | macOS自体が非対応 |

各macOSがサポートするMacを使用してください。SequoiaとTahoeは実装の対象ですが、
実機での認証は未確認です。Golden Gateについても、すべてのMacで確認済みという意味ではありません。
HomebrewがRosettaで動いている場合も、Mac本体のCPUに合わせたパッケージを選びます。
`sudo` 自体はネイティブ実行が必要です。

**Apple Watch** を使う場合は、先に
[Macのロック解除や承認にApple Watchを使える状態](https://support.apple.com/ja-jp/102442)
にしてください。Wi-FiとBluetoothを有効にし、2ファクタ認証を設定した同じApple Accountを使い、
システム設定でApple Watchによるロック解除を有効にします。
パスコードを設定したWatchを装着し、ロックを解除してMacの近くで使用してください。

**Touch ID** を使う場合は、対応するMacまたはキーボードで、システム設定から指紋を登録してください。
Touch IDの利用にApple Watchは不要です。Apple Watchの利用にTouch ID搭載機器は不要です。
どの認証方法を提示するかはmacOSが判断します。

## インストール

次のコマンドでインストールできます。

```sh
brew tap rioriost/cask
brew install --cask rioriost/cask/pam-watchid
```

インストーラが管理者の承認を求める場合があります。署名・公証済みのパッケージを
`/Library/Security/pam_watchid/` に配置しますが、**PAM設定は変更しません**。
Homebrewは通常のユーザーで実行し、`sudo brew` は使用しないでください。

## sudoで有効にする

認証設定を変更する間は、復旧に使える管理者権限のターミナルを別に確保してください。
既存のPAM設定を削除したり、`/etc/pam.d/sudo` を変更したりしないでください。

sudoのローカル設定を開きます。ファイルがなければ作成します。

```sh
sudoedit /etc/pam.d/sudo_local
```

他の `auth` 行より前に、次の1行を一度だけ追加します。

```text
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
```

保存したら、別のターミナルで試してください。

```sh
sudo -k
sudo -v
```

システムの案内に従い、Touch IDに触れるか、Apple Watchのサイドボタンをダブルクリックして承認します。
認証できない場合やキャンセルした場合は、既存のsudo認証に戻ります。
ほかに有効なPAM認証があれば、それらによる認証も引き続き可能です。
このモジュールが既存の認証方法を置き換えたり無効にしたりすることはありません。

sudoは通常、認証成功を一定時間キャッシュするため、毎回のコマンドで承認が求められるわけではありません。
`sudo -k` で現在の認証キャッシュを無効にできます。

## 更新・アンインストール

**最初に `/etc/pam.d/sudo_local` から、追加した `pam_watchid.so` の行だけを削除してください。**
無関係な設定は残してください。

更新する場合：

```sh
brew upgrade --cask rioriost/cask/pam-watchid
```

更新後、引き続き使う場合は設定行を追加し直してください。
利用中のPAMモジュールを削除・置換しないよう、更新時にも一度無効化する必要があります。

アンインストールする場合：

```sh
brew uninstall --cask rioriost/cask/pam-watchid
```

`/etc/pam.d` にモジュールへの有効な参照が残っている場合、削除は拒否されます。
アンインストーラが認証設定を自動で書き換えることはありません。

## 制限・困ったとき

- 現在ログインしているローカルのデスクトップユーザーで使用してください。
  SSH、画面のないセッション、デスクトップと切り離されたり一致しなかったりする
  ターミナルマルチプレクサのセッションはサポート対象外です。通常のsudo認証を使用してください。
- 非対話の自動処理はサポート対象外です。macOSのPAMからは `sudo -n` の指定を判別できないため、
  `-n` を付けてもシステムの認証画面が表示される可能性があります。
  Askpassを使う場合は既存のPAM認証に戻ります。
- 応答しない場合、通常の認証に戻るまで最大約1分かかることがあります。
  キャンセル、ロック中・利用不可のWatch、失敗したTouch IDが認証成功になることはありません。
- 認証画面が出ない場合は、有効化の設定行、ターミナルとデスクトップのユーザーの一致、
  sudoのネイティブ実行を確認してください。まずmacOS標準のWatch承認やTouch IDが動くことを確認します。
- 復旧が必要な場合は、別に確保した管理者ターミナルでpam_watchidの設定行だけを削除してください。
  標準のパスワード認証設定は残してください。SIPやGatekeeperを無効にする必要はありません。

## ライセンス

[MIT](LICENSE)。
[pam-watchid](https://github.com/biscuitehh/pam-watchid) の外形的な機能を参考にした独立実装です。

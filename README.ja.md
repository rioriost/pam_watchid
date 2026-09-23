# pam_watchid

[English](README.md) | [日本語](README.ja.md)

Macの `sudo` を **Apple WatchまたはTouch ID** で承認できます。どちらも利用できない場合、
キャンセルした場合、タイムアウトした場合は、通常のパスワード入力など、既存のsudo認証に戻ります。

**リリース状況：** 自動設定に対応する **0.2.1** を準備中です。
現在公開中の[0.1.1プレリリース](https://github.com/rioriost/pam_watchid/releases/tag/v0.1.1)は、
引き続き[手動での有効化](https://github.com/rioriost/pam_watchid/blob/v0.1.1/README.ja.md#sudoで有効にする)
が必要です（ファイル編集には `/usr/bin/sudo -e` を使ってください）。
Golden Gate 27搭載のApple Silicon Mac 1台で、Apple Watch、Touch ID、キャンセル、
パスワードへの切り替えを確認済みですが、ほかのハードウェア・OSや追加のセッション条件は未確認です。

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

Homebrewは通常のユーザーで実行し、`sudo brew` は使用しないでください。
インストーラが管理者の承認を求めます。0.2.1以降は**エディタでの編集は不要**です。
署名・公証済みのファイルを `/Library/Security/pam_watchid/` に配置し、
モジュールとヘルパーを確認してから、`sudo_local` をバックアップし、自動で有効化します。

バックアップは `/private/var/db/pam_watchid/` 以下の管理者専用ディレクトリに保存し、
アンインストール後も残します。`/etc/pam.d/sudo_local` がない場合は、その状態を記録してから作成します。
`/etc/pam.d/sudo` は変更しません。

次の設定行を、識別用コメントで囲んだ管理対象ブロックとして追加します。
既存の設定は削除せず、再インストールで同じ行を重複追加することもありません。

```text
auth sufficient /Library/Security/pam_watchid/pam_watchid.so
```

安全に変更できない独自のPAM設定がある場合は、勝手に上書きせず理由を表示して停止します。
インストール中は復旧に使える管理者ターミナルを別に確保してください。

アンインストールせず、自動設定した認証だけを無効にする場合：

```sh
sudo /Library/Security/pam_watchid/uninstall.sh --disable
```

再インストールすると、同じ確認とバックアップを行って再度有効化します。

## sudoを使う

インストール後、別のターミナルで試してください。

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

0.2.1以降のインストーラで自動設定した場合、次のコマンドで更新できます。

```sh
brew upgrade --cask rioriost/cask/pam-watchid
```

ファイルを置き換える前に管理対象の設定行を一時的に外し、新しいインストール内容を確認してから追加し直します。
更新のたびにエディタでPAM設定を変更する必要はありません。

アンインストールする場合：

```sh
brew uninstall --cask rioriost/cask/pam-watchid
```

モジュールを削除する前に、インストーラが追加した管理対象の設定だけを取り除きます。
ほかの設定、後から管理者が加えた変更、バックアップは残します。
管理対象ブロックが書き換えられていたり、別のPAMファイルに参照があったりする場合は、
削除対象を推測せず停止します。

**手動で有効化した0.1.1からの更新：** 最初の1回だけ、既存の `pam_watchid.so` の設定行を外してから
`brew upgrade` を実行してください。編集には `/usr/bin/sudo -e /etc/pam.d/sudo_local` を使い、
無関係な行は残してください。旧版のアンインストーラによる制約であり、
自動設定に移行した後の更新ではこの操作は不要です。

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
- 復旧が必要な場合は、別に確保した管理者ターミナルからアンインストールするか、
  pam_watchidの管理対象ブロック全体だけを取り除き、ほかの設定を残してください。
  バックアップは `/private/var/db/pam_watchid/` 以下に残りますが、
  後から加えた変更を古いバックアップで上書きしないようにしてください。SIPやGatekeeperは無効にしないでください。

## ライセンス

[MIT](LICENSE)。
[pam-watchid](https://github.com/biscuitehh/pam-watchid) の外形的な機能を参考にした独立実装です。

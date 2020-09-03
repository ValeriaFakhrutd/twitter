twitter
A Twitter simulator. Users join a server, create usernames, can follow/unfollow other users, send their tweets, favourite tweets, see the tweets of people they are following etc. A server has it is own log for all activities. Any number of users can join the server Commands that any user has:

follow <username> - start following a <username>, allows to see what others have sent
  
unfollow <username> - stop following <username>
  
show - shows all the msgs of users from your following

send - sends user's msg

quit - disconnect from the server

To connect to a server use nc -C localhost/hostname <port#>

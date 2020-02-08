<?php if (!defined('GUEST')) die('go away'); ?>

<div class="container">
    <div class="jumbotron">
        <h1>Danger, Will Robinson!</h1>
        <p>
            Hmmm...something went wrong:<br>
            <?php echo "<b>Error " . $_SESSION['error_code'] . "</b>: <i>" . $_SESSION['error_message'] . "</i>"; ?>
            <br>
            <a href="<?php echo $cfg_url_base; ?>" class="btn btn-primary btn-lg">Lets retry this!</a>
            <br>
            <span style="font-size:80%;">
                For support ask in <a href="https://brave-collective.slack.com/" target="_blank">Slack</a>
                in the channel #it-help, in the in-game channel "Brave IT Team" or write to
                support@bravecollective.freshdesk.com.
            </span>
        </p>
    </div>
</div>

<?php sdestroy(); ?>

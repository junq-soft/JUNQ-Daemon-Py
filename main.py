import junq_daemon
import logging


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='junq-damon.log', level=logging.INFO, format="%(asctime)s %(levelname)s::%(message)s", filemode="w")
    
    d = junq_daemon.Daemon(logger)
    d.check_ygg_proxy()
    d.create_server()
    d.loop()
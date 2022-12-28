import logging
from logging import handlers


class Logger:
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info',
                 fmt='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)                     # set up log format
        self.logger.setLevel(self.level_relations.get(level))   # set up log level

        # print log to console
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(format_str)
        self.logger.addHandler(stream_handler)

        # Max file size: 500MB
        rotating_file_handler = handlers.RotatingFileHandler(
            filename=filename, mode='a', maxBytes=1024 * 1024 * 500, backupCount=5, encoding='utf-8')
        rotating_file_handler.setFormatter(format_str)
        self.logger.addHandler(rotating_file_handler)


if __name__ == '__main__':
    log = Logger('all.log', level='debug')
    log.logger.info('[test log] hello miffy')
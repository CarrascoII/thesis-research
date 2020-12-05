import sys, getopt
import matplotlib.pyplot as plt
import utils
# import seaborn as sns


def save_fig(fig, fname):
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plt.cla()

def custom_errorbar(x, y, e, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def multiple_custom_plots(x, y1, y2, ax=None, title=None, ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()

    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

# def custom_hist(x, ax=None, title=None, ylabel=None, kwargs={}):
#     if ax is None:
#         ax = plt.gca()

#     # Alt.1 Using simple histogram
#     ax.hist(x, **kwargs)

#     # Alt.2 Using a kernel density estimation
#     for i in range(len(x)):
#         sns.kdeplot(x[i], ax=ax, label=kwargs['label'][i])

#     ax.set(xlabel=ylabel, title=title)
#     ax.legend()

#     return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel=None, xticks=None, xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def make_errorbar(ylabel, file_path, stats):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    params2 = {'color': 'red'}
    params4 = {'color': 'blue'}

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    ax1 = custom_errorbar(stats['data_size'], stats['mean_out'], stats['stdev_out'], ax=ax1,
                            title=operations[0], ylabel=ylabel, kwargs=params2)
    ax2 = custom_errorbar(stats['data_size'], stats['mean_in'], stats['stdev_in'], ax=ax2,
                            title=operations[1], ylabel=ylabel, kwargs=params4)

    save_fig(fig, file_path + ylabel + '_deviation.png')

def make_plot(ylabel, file_path, stats):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))

    params1 = {'color': 'red', 'linestyle': '-'}
    params2 = {'color': 'blue', 'linestyle': '--'}

    if file_path.find('cipher') != -1:
        params1['label'] = 'encryption'
        params2['label'] = 'decryption'
    elif file_path.find('md') != -1:
        params1['label'] = 'digest'
        params2['label'] = 'verify'

    ax1 = multiple_custom_plots(stats['data_size'], stats['mean_out'], stats['mean_in'],
                                ax=ax1, title='Mean', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(stats['data_size'], stats['median_out'], stats['median_in'],
                                ax=ax2, title='Median', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(stats['data_size'], stats['mode_out'], stats['mode_in'],
                                ax=ax3, title='Mode', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    save_fig(fig, file_path + ylabel + '_statistics.png')

# def make_hist(ylabel, file_path, data_out, data_in):
#     fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

#     operations = None
#     x1 = []
#     x2 = []
#     params1 = {'label': list(data_out.keys())}
#     params2 = {'label': list(data_in.keys())}

#     if file_path.find('cipher') != -1:
#         operations = ['cipher', 'decipher']
#     elif file_path.find('md') != -1:
#         operations = ['hash', 'verify']

#     for key in data_out:
#         x1.append(data_out[key])

#     for key in data_in:
#         x2.append(data_in[key])

#     ax1 = custom_hist(x1, ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params1)
#     ax2 = custom_hist(x2, ax=ax2, title=operations[1], ylabel=ylabel, kwargs=params2)

#     save_fig(fig, file_path + ylabel + '_hist.png')

def make_scatter(ylabel, file_path, data_out, data_in):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    x1 = []
    y1 = []
    xticks1 = [tick + 1 for tick in range(len(data_out))]
    xtickslabels1 = list(data_out.keys())

    x2 = []
    y2 = []
    xticks2 = [tick + 1 for tick in range(len(data_in))]
    xtickslabels2 = list(data_in.keys())

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    i = 0
    for key in data_out:
        x1 += [xticks1[i] for j in range(len(data_out[key]))]
        y1 += data_out[key]
        i += 1

    i = 0
    for key in data_in:
        x2 += [xticks2[i] for j in range(len(data_in[key]))]
        y2 += data_in[key]
        i += 1

    ax1 = custom_scatter(x1, y1, ax=ax1, title=operations[0], xticks=xticks1,
                            xtickslabels=xtickslabels1, ylabel=ylabel, kwargs={'color': 'red'})
    ax2 = custom_scatter(x2, y2, ax=ax2, title=operations[1], xticks=xticks2,
                            xtickslabels=xtickslabels2, ylabel=ylabel, kwargs={'color': 'blue'})

    save_fig(fig, file_path + ylabel + '_distribution.png')

def make_figs(filename, weight=1.5, strlen=40, spacing=''):
    path = filename.replace('data.csv', '')

    print(spacing + f'Parsing obtained data'.ljust(strlen, '.'), end=' ')
    data, headers = utils.parse_csv_to_data(filename)
    print(f'ok')

    # total1 = []
    # for header in headers:
    #     tmp = 0
    #     for data_size in data[header + '_out']:
    #         tmp += len(data[header + '_out'][data_size])
    #     total1.append(tmp)

    #     tmp = 0
    #     for data_size in data[header + '_in']:
    #         tmp += len(data[header + '_in'][data_size])
    #     total1.append(tmp)

    if weight != 0:
        print(spacing + f'Removing outliers from data'.ljust(strlen, '.'), end=' ')
        data = utils.filter_iqr(data, headers, weight=weight)
        print(f'ok')
    
    # total2 = []
    # for header in headers:
    #     tmp = 0
    #     for data_size in data[header + '_out']:
    #         tmp += len(data[header + '_out'][data_size])
    #     total2.append(tmp)

    #     tmp = 0
    #     for data_size in data[header + '_in']:
    #         tmp += len(data[header + '_in'][data_size])
    #     total2.append(tmp)

    # print(f'cycles_out: {total2[0]/total1[0]}')
    # print(f'cycles_in: {total2[1]/total1[1]}')
    # print(f'time_out: {total2[2]/total1[2]}')
    # print(f'time_in: {total2[3]/total1[3]}')

    for header in headers:
        print(spacing + f'[{header}] Calculating statistics'.ljust(strlen, '.'), end=' ')
        statistics = utils.calc_statistics(data[header + '_out'], data[header + '_in'])
        print(f'ok')

        print(spacing + f'[{header}] Generating figures'.ljust(strlen, '.'), end=' ')
        make_scatter(header, path, data[header + '_out'], data[header + '_in'])
        # make_hist(header, path, data[header + '_out'], data[header + '_in'])
        make_plot(header, path, statistics)
        make_errorbar(header, path, statistics)
        print(f'ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:c:m:', ['help', 'filter=', 'cfile=', 'mfile='])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "plotter.py -h" for help')
        sys.exit(2)

    if args:
        print(f'Could not parse {args}')
        sys.exit(2)

    weight = 1.5
    algs = {}

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'plotter.py [-f <weight>] [-c <cipher_file>] [-m <md_file>]')
            print(f'plotter.py [--filter=<weight>] [--cfile=<cipher_file>] [--mfile=<md_file>]')
            sys.exit(0)
        if opt in ('-f', '--nfilter'):
            weight = float(arg)
        elif opt in ('-c', '--cfile') or opt in ('-m', '--mfile'):
            algs[opt] = arg
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    for key in algs:
        make_figs(algs[key], weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])